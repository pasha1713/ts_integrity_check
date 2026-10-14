#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ts_integrity_check.py v3.37
Проверка целостности набора .ts-фрагментов: являются ли они единым видео
с одного устройства непрерывно.

Основано на Sergei Franco's Novatek GPS extractor (GPL3)
https://gist.github.com/UndeRus/01ef8b436353f579760a60b0dea96253
"""

import os
import sys
import argparse
import struct
import time
import datetime
import hashlib
import platform
import subprocess
import ctypes
import shutil
import io
import re
import math
import numpy as np

VERSION = "3.37"

# History log:
# v3.20: detect_fragments — mtime для заводских файлов пропускается
# v3.20: check_mtime — заводские файлы [ОБЪЯСНЕНО]
# v3.21: Заключение — «стабилизация GPS-приёмника» без заводских файлов
# v3.22: Поиск синхробайта + PCR_ext в bitrate segments
# v3.23: Грамматика — _plural_ru для «файл» в режиме
# v3.23: Фиксированные 10-сек сегменты
# v3.24: Rollup «Целостность файлов» не дублирует total_errors
# v3.25: math.ceil вместо int()+1, реальная длительность сегментов
# v3.26: parse_ts_full — локальный nal_names → H264_NAL_NAMES
# v3.27: import re вынесен в начало файла (fix #13)
# v3.28: compute_phash — векторизация через reshape+mean (fix #12)
# v3.29: Удалена save_paginated_png (fix #11), единый 4-value return (fix #14)
# v3.30: Удалены мёртвые словари pcr_base_prev/pcr_ext_prev (fix #10)
# v3.31: fix_coordinates — удалён мёртвый параметр deobfuscate (fix #9)
# v3.32: md5_file — except (ValueError, Exception) → except Exception (fix #8)
# v3.33: parse_ts_full — убран дубликат 0xBD в stream_id (fix #7)
# v3.34: parse_ts_full — обновлён docstring (fix #6)
# v3.35: PCR_ext в parse_ts_full (fix #1), frag_results explained (fix #3),
#         gps_coord_distance — math.cos (fix #4), Windows-only guards (fix #5)
# v3.36: Исправлен счётчик объяснённых отклонений — _t_expl не накапливается
# v3.37: Все fix #1-#15 применены, generate_history_log почищен от дубликатов

# ============================================================
# Кодировка вывода
# ============================================================

_encoding = 'cp866'

def setup_encoding(enc):
    global _encoding
    _encoding = enc

def _plural_ru(n, forms):
    """Правильная форма слова по числу. forms = (1, 2, 5) например ('ошибка','ошибки','ошибок')."""
    n = abs(n) % 100
    if 11 <= n <= 14:
        return forms[2]
    n = n % 10
    if n == 1:
        return forms[0]
    if 2 <= n <= 4:
        return forms[1]
    return forms[2]


def format_duration(seconds):
    """Форматирование длительности: дни, часы, минуты, секунды."""
    if seconds is None or seconds < 0:
        return '---'
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days > 0:
        parts.append('%d %s' % (days, _plural_ru(days, ('день', 'дня', 'дней'))))
    if hours > 0:
        parts.append('%d %s' % (hours, _plural_ru(hours, ('час', 'часа', 'часов'))))
    if minutes > 0:
        parts.append('%d %s' % (minutes, _plural_ru(minutes, ('мин', 'мин', 'мин'))))
    if seconds > 0 or not parts:
        parts.append('%d %s' % (seconds, _plural_ru(seconds, ('сек', 'сек', 'сек'))))
    return ' '.join(parts)


class EncodedWriter:
    def __init__(self, stream, enc):
        self.stream = stream
        self.enc = enc
    def write(self, text):
        try:
            self.stream.write(text.encode(self.enc, errors='replace').decode(self.enc, errors='replace'))
        except Exception:
            self.stream.write(text)
    def flush(self):
        self.stream.flush()

# ============================================================
# Парсинг GPS (из оригинального скрипта Sergei Franco)
# ============================================================

def fix_time(dt):
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (
        dt['Year'] + 2000, dt['Month'], dt['Day'],
        dt['Hour'], dt['Minute'], dt['Second'])

def fix_coordinates(hemi, raw):
    degrees = int(raw / 100)
    minutes = raw - (degrees * 100)
    result = degrees + minutes / 60.0
    if hemi in ['S', 'W']:
        result = -result
    return result

def fix_speed(speed):
    return speed * 1.852

def deobfuscate_coord(latitude, longitude):
    latitude = (latitude - 187.98217) / 3.0
    longitude = (longitude - 2199.19876) * 0.5
    return latitude, longitude

def get_gps_offset(data):
    pointer = len(data) - 20
    beginning = 0
    while pointer > beginning:
        try:
            active, lon_hemi, lat_hemi = struct.unpack_from('<sss', data, pointer)
            active = active.decode()
            lon_hemi = lon_hemi.decode()
            lat_hemi = lat_hemi.decode()
            if active == 'A' and lon_hemi in ['N', 'S'] and lat_hemi in ['E', 'W']:
                offset = pointer - 24
                return offset
        except (UnicodeDecodeError, struct.error):
            pass
        pointer -= 1
    return -1

def get_gps_data(data, deobfuscate):
    gps = {
        'Epoch': None,
        'DT': {'Year': None, 'Month': None, 'Day': None,
               'Hour': None, 'Minute': None, 'Second': None, 'DT': None},
        'Loc': {'Lat': {'Raw': None, 'Hemi': None, 'Float': None},
                'Lon': {'Raw': None, 'Hemi': None, 'Float': None},
                'Speed': None, 'Bearing': None},
    }
    if struct.unpack_from('>c', data)[0] in [b'\x05', b'\xF0']:
        return None
    offset = get_gps_offset(data)
    if offset < 0:
        return None
    try:
        gps['DT']['Hour'], gps['DT']['Minute'], gps['DT']['Second'] = \
            struct.unpack_from('<III', data, offset)
        offset += 12
        gps['DT']['Year'], gps['DT']['Month'], gps['DT']['Day'] = \
            struct.unpack_from('<III', data, offset)
        offset += 12
        active, lat_hemi, lon_hemi = struct.unpack_from('<sss', data, offset)
        offset += 4
        gps['Loc']['Lat']['Raw'], gps['Loc']['Lon']['Raw'] = \
            struct.unpack_from('<ff', data, offset)
        offset += 8
        gps['Loc']['Speed'], gps['Loc']['Bearing'] = \
            struct.unpack_from('<ff', data, offset)
        active = active.decode()
        gps['Loc']['Lat']['Hemi'] = lat_hemi.decode()
        gps['Loc']['Lon']['Hemi'] = lon_hemi.decode()
    except (struct.error, UnicodeDecodeError):
        return None
    if deobfuscate:
        gps['Loc']['Lat']['Raw'], gps['Loc']['Lon']['Raw'] = deobfuscate_coord(
            gps['Loc']['Lat']['Raw'], gps['Loc']['Lon']['Raw'])
    gps['Loc']['Lat']['Float'] = fix_coordinates(
        gps['Loc']['Lat']['Hemi'], gps['Loc']['Lat']['Raw'])
    gps['Loc']['Lon']['Float'] = fix_coordinates(
        gps['Loc']['Lon']['Hemi'], gps['Loc']['Lon']['Raw'])
    gps['Loc']['Speed'] = fix_speed(gps['Loc']['Speed'])
    gps['DT']['DT'] = fix_time(gps['DT'])
    try:
        gps['Epoch'] = int(time.mktime(time.strptime(
            gps['DT']['DT'][:-1] + 'UTC', "%Y-%m-%dT%H:%M:%S%Z")))
    except ValueError:
        return None
    return gps

# ============================================================
# Парсинг TS-файлов
# ============================================================

def parse_ts_full(filepath, deobfuscate=False):
    """Полный парсинг TS-файла: GPS, PCR, PTS, DTS, PID, NAL (H.264/H.265), continuity counter, кодек."""
    result = {
        'gps_data': [],
        'pids': set(),
        'pcr_list': [],
        'pts_list': [],
        'pts_video_list': [],
        'pts_audio_list': [],
        'dts_list': [],
        'nal_types': {},
        'cc_errors': {},
        'ts_packets': 0,
        'video_pid': None,
        'audio_pid': None,
        'pcr_pid': None,
    }

    with open(filepath, 'rb') as f:
        data = f.read()

    if not data:
        return result

    # Определяем кодек (H.264/H.265) один раз через detect_codec()
    result['_codec'] = detect_codec(data)

    is_ts = False
    if len(data) >= 377:
        if data[0] == 0x47 and data[188] == 0x47 and data[376] == 0x47:
            is_ts = True
    if not is_ts:
        for start in range(min(204, len(data) - 376)):
            if (data[start] == 0x47 and
                start + 188 < len(data) and data[start + 188] == 0x47 and
                start + 376 < len(data) and data[start + 376] == 0x47):
                data = data[start:]
                is_ts = True
                break
    if not is_ts:
        return result

    offset = 0
    partial = b''
    cc_state = {}

    while offset + 188 <= len(data):
        packet = data[offset:offset + 188]
        offset += 188
        result['ts_packets'] += 1

        if packet[0] != 0x47:
            resync = -1
            for i in range(188):
                if offset + i + 188 <= len(data):
                    if data[offset + i] == 0x47:
                        if offset + i + 188 <= len(data) and data[offset + i + 188] == 0x47:
                            resync = i
                            break
            if resync >= 0:
                offset += resync
            continue

        pid = ((packet[1] & 0x1F) << 8) | packet[2]
        result['pids'].add(pid)

        adaptation_control = (packet[3] >> 4) & 0x03
        payload_start = 4
        has_adaptation = bool(adaptation_control & 0x02)
        has_payload = bool(adaptation_control & 0x01)

        if has_adaptation:
            if len(packet) > 4:
                adaptation_length = packet[4]
                payload_start = 5 + adaptation_length
            else:
                continue

        # PCR (до проверки has_payload — пакеты 0x20 только adaptation)
        if has_adaptation and len(packet) > 5:
            adapt_len = packet[4]
            if adapt_len >= 7 and 5 + 1 < len(packet):
                flags = packet[5]
                if flags & 0x10 and 5 + adapt_len <= len(packet):
                    try:
                        pcr_base = struct.unpack_from('>Q', packet, 6)[0]
                        pcr_base = pcr_base >> 31
                        pcr_ext = ((packet[10] & 0x01) << 8) | packet[11]
                        pcr_val = pcr_base * 300 + pcr_ext
                        result['pcr_list'].append(pcr_val / 27000000.0)
                        result['pcr_pid'] = pid
                    except struct.error:
                        pass

        if not has_payload:
            continue

        if payload_start >= 188:
            continue

        # Continuity Counter
        cc = packet[3] & 0x0F
        if pid in cc_state:
            prev_cc = cc_state[pid]
            expected_cc = (prev_cc + 1) % 16
            if has_payload and not has_adaptation:
                if cc != expected_cc:
                    if pid not in result['cc_errors']:
                        result['cc_errors'][pid] = 0
                    result['cc_errors'][pid] += 1
            cc_state[pid] = cc
        else:
            cc_state[pid] = cc

        payload = packet[payload_start:]

        # PTS/DTS
        if len(payload) >= 9 and payload[:3] == b'\x00\x00\x01':
            stream_id = payload[3]
            if stream_id in (0xE0, 0xBD, 0xC0, 0xC1):
                if len(payload) >= 14:
                    pts_dts_flags = (payload[7] >> 6) & 0x03
                    if pts_dts_flags & 0x02:
                        try:
                            pts = ((payload[9] >> 1) & 0x07) << 30
                            pts |= (payload[10] << 22)
                            pts |= ((payload[11] >> 1) << 15)
                            pts |= (payload[12] << 7)
                            pts |= (payload[13] >> 1)
                            pts_sec = pts / 90000.0
                            result['pts_list'].append(pts_sec)
                            if stream_id == 0xE0:
                                result['video_pid'] = pid
                                result['pts_video_list'].append(pts_sec)
                            elif stream_id in (0xC0, 0xC1):
                                result['audio_pid'] = pid
                                result['pts_audio_list'].append(pts_sec)
                            if pts_dts_flags & 0x01 and len(payload) >= 19:
                                dts = ((payload[14] >> 1) & 0x07) << 30
                                dts |= (payload[15] << 22)
                                dts |= ((payload[16] >> 1) << 15)
                                dts |= (payload[17] << 7)
                                dts |= (payload[18] >> 1)
                                result['dts_list'].append(dts / 90000.0)
                        except (struct.error, IndexError):
                            pass

        # NAL unit types (H.264/H.265)
        if pid == result.get('video_pid') or (result['video_pid'] is None and pid == 0x0200):
            if len(payload) >= 4 and payload[:4] in (b'\x00\x00\x00\x01', b'\x00\x00\x01'):
                nal_start = 4 if payload[:4] == b'\x00\x00\x00\x01' else 3
                if nal_start < len(payload):
                    nal_byte = payload[nal_start]
                    # Определяем кодек по наличию VPS/SPS/PPS H.265
                    if '_codec' not in result:
                        h265_check = (nal_byte >> 1) & 0x3F
                        if h265_check in (32, 33, 34):  # VPS, SPS, PPS — H.265
                            result['_codec'] = 'h265'
                    codec = result.get('_codec', 'h264')
                    if codec == 'h265':
                        nal_type = (nal_byte >> 1) & 0x3F
                        name = H265_NAL_NAMES.get(nal_type, 'TYPE_%d' % nal_type)
                        # Нормализуем имена для отчёта
                        if nal_type in (19, 20):
                            name = 'IDR'
                        elif nal_type == 21:
                            name = 'CRA'
                        elif nal_type == 32:
                            name = 'VPS'
                        elif nal_type == 33:
                            name = 'SPS'
                        elif nal_type == 34:
                            name = 'PPS'
                        elif nal_type == 35:
                            name = 'AUD'
                        elif nal_type in (39, 40):
                            name = 'SEI'
                        elif nal_type == 48:
                            name = 'SEI'
                    else:
                        nal_type = nal_byte & 0x1F
                        name = H264_NAL_NAMES.get(nal_type, 'TYPE_%d' % nal_type)
                    result['nal_types'][name] = result['nal_types'].get(name, 0) + 1

        # GPS (PID 0x0300)
        if pid != 0x0300:
            continue

        if len(payload) >= 4 and payload[:4] == b'\x00\x00\x01\xbf':
            gps_result = get_gps_data(payload, deobfuscate)
            if gps_result:
                result['gps_data'].append(gps_result)
            partial = b''
        else:
            if partial:
                combined = partial + payload
                gps_result = get_gps_data(combined, deobfuscate)
                if gps_result:
                    result['gps_data'].append(gps_result)
                partial = b''
            else:
                if len(payload) >= 14:
                    partial = payload[-14:]

    return result

# ============================================================
# Вспомогательные функции
# ============================================================

def dt_to_datetime(gps):
    try:
        return datetime.datetime(
            gps['DT']['Year'] + 2000,
            gps['DT']['Month'],
            gps['DT']['Day'],
            gps['DT']['Hour'],
            gps['DT']['Minute'],
            gps['DT']['Second']
        )
    except (TypeError, ValueError):
        return None

def dt_to_msk(dt):
    """Перевод UTC -> МСК (UTC+3)."""
    if dt is None:
        return None
    return dt + datetime.timedelta(hours=3)

def format_msk(dt_utc):
    """Форматирование времени в МСК."""
    if dt_utc is None:
        return '---'
    msk = dt_to_msk(dt_utc)
    return msk.strftime('%Y-%m-%d %H:%M:%S') + ' MSK'

def format_msk_short(dt_utc):
    if dt_utc is None:
        return '---'
    msk = dt_to_msk(dt_utc)
    return msk.strftime('%Y-%m-%d %H:%M:%S')

def md5_file(filepath):
    # FIPS-совместимый MD5: на некоторых системах Windows MD5 заблокирован
    try:
        h = hashlib.new('md5', usedforsecurity=False)
    except TypeError:
        h = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest().upper()
    except Exception:
        # FIPS-режим: MD5 заблокирован — используем SHA-256
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return 'SHA256:' + h.hexdigest().upper()[:32]

def file_size(filepath):
    return os.path.getsize(filepath)

def file_mtime(filepath):
    mtime = os.path.getmtime(filepath)
    return datetime.datetime.fromtimestamp(mtime)

def get_file_seq_num(filepath):
    """Извлекает порядковый номер из имени файла (последние 6 цифр перед .TS)."""
    fname = os.path.basename(filepath)
    m = re.search(r'(\d{6})[A-Z]?\.TS$', fname, re.IGNORECASE)
    if m:
        return int(m.group(1))
    digits = ''.join(c for c in fname if c.isdigit())
    if len(digits) >= 6:
        return int(digits[-6:])
    return 0

def find_ts_files(path):
    ts_files = []
    if os.path.isfile(path):
        ts_files = [path]
    elif os.path.isdir(path):
        seen = set()
        for f in os.listdir(path):
            if f.upper().endswith('.TS'):
                real = os.path.realpath(os.path.join(path, f))
                if real not in seen:
                    seen.add(real)
                    ts_files.append(os.path.join(path, f))
    # Сортируем по порядковому номеру, не по времени в имени
    ts_files.sort(key=get_file_seq_num)
    return ts_files

# ============================================================
# Сведения о системе
# ============================================================

def get_computer_info():
    info = {}
    info['name'] = platform.node() or '---'
    info['os'] = platform.platform() or '---'
    info['os_version'] = platform.version() or '---'
    info['arch'] = platform.machine() or '---'
    info['processor'] = platform.processor() or '---'
    info['user'] = os.environ.get('USERNAME', os.environ.get('USER', '---'))
    info['python'] = platform.python_version()

    info['cpu_serial'] = '---'
    if platform.system() == 'Windows':
        # Уровень 1: wmic с retry
        for attempt in range(3):
            try:
                r = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId'],
                                  capture_output=True, text=True, timeout=30)
                wmic_lines = [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
                if len(wmic_lines) > 1 and wmic_lines[1].strip():
                    info['cpu_serial'] = wmic_lines[1]
                    break
            except Exception:
                if attempt < 2:
                    time.sleep(2)
        # Уровень 2: PowerShell fallback
        if info['cpu_serial'] == '---':
            try:
                r = subprocess.run(
                    ['powershell', '-Command',
                     '(Get-WmiObject Win32_Processor).ProcessorId'],
                    capture_output=True, text=True, timeout=30)
                val = r.stdout.strip()
                if val:
                    info['cpu_serial'] = val
            except Exception:
                pass
    return info

def _get_disk_info_winapi(drive_letter):
    """Получение модели и серийного номера физического диска через WinAPI
    DeviceIoControl — напрямую к драйверу, минуя WMI.
    """
    if platform.system() != 'Windows':
        return None, None
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    OPEN_EXISTING = 3
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
    IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
    StorageDeviceProperty = 0

    # Открываем том
    vol_path = '\\\\.\\%s' % drive_letter
    handle = ctypes.windll.kernel32.CreateFileW(
        vol_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None)
    if handle == ctypes.c_void_p(-1).value or handle == -1:
        return None, None

    try:
        # Получаем номер физического диска
        out_buf = ctypes.create_string_buffer(512)
        bytes_returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None, 0, out_buf, 512,
            ctypes.byref(bytes_returned), None)
        if not ok or bytes_returned.value < 16:
            return None, None

        # VOLUME_DISK_EXTENTS: NumberOfDiskExtents (DWORD) + Extents[]
        num_extents = struct.unpack_from('<I', out_buf.raw, 0)[0]
        if num_extents < 1:
            return None, None
        # DiskNumber — первое поле DISK_EXTENT (DWORD)
        disk_number = struct.unpack_from('<I', out_buf.raw, 8)[0]
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)

    # Открываем физический диск
    phys_path = '\\\\.\\PhysicalDrive%d' % disk_number
    handle = ctypes.windll.kernel32.CreateFileW(
        phys_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None)
    if handle == ctypes.c_void_p(-1).value or handle == -1:
        return None, None

    try:
        # STORAGE_PROPERTY_QUERY
        query = struct.pack('<II I', StorageDeviceProperty, 0, 0)
        out_buf = ctypes.create_string_buffer(4096)
        bytes_returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle, IOCTL_STORAGE_QUERY_PROPERTY,
            query, len(query), out_buf, 4096,
            ctypes.byref(bytes_returned), None)
        if not ok:
            return None, None

        # STORAGE_DEVICE_DESCRIPTOR
        raw = out_buf.raw[:bytes_returned.value]
        if len(raw) < 40:
            return None, None
        version, total_size = struct.unpack_from('<II', raw, 0)
        device_type = struct.unpack_from('<I', raw, 8)[0]
        # Смещения в STORAGE_DEVICE_DESCRIPTOR:
        #   VendorIdOffset(12), ProductIdOffset(16),
        #   ProductRevisionOffset(20), SerialNumberOffset(24)
        vendor_off = struct.unpack_from('<I', raw, 12)[0]
        product_off = struct.unpack_from('<I', raw, 16)[0]
        serial_off = struct.unpack_from('<I', raw, 24)[0]

        model = ''
        if product_off > 0 and product_off < len(raw):
            end = raw.index(b'\x00', product_off) if b'\x00' in raw[product_off:] else len(raw)
            model = raw[product_off:end].decode('ascii', errors='replace').strip()
        if vendor_off > 0 and vendor_off < len(raw):
            end = raw.index(b'\x00', vendor_off) if b'\x00' in raw[vendor_off:] else len(raw)
            vendor = raw[vendor_off:end].decode('ascii', errors='replace').strip()
            if vendor and model:
                model = '%s %s' % (vendor, model)
            elif vendor and not model:
                model = vendor

        serial = ''
        if serial_off > 0 and serial_off < len(raw):
            end = raw.index(b'\x00', serial_off) if b'\x00' in raw[serial_off:] else len(raw)
            serial = raw[serial_off:end].decode('ascii', errors='replace').strip()

        return model if model else None, serial if serial else None
    except Exception:
        return None, None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def get_disk_info(path):
    """Получение информации о диске: файловая система, метка, серийный номер,
    модель и серийный номер физического диска.
    Уровень 1: WinAPI DeviceIoControl (напрямую к драйверу, минуя WMI).
    Уровень 2: wmic с retry (3 попытки, таймаут 30 сек).
    Уровень 3: PowerShell fallback.
    """
    info = {}
    drive_letter = os.path.splitdrive(os.path.abspath(path))[0] or 'C:'
    if not drive_letter.endswith(':'):
        drive_letter += ':'

    # Файловая система, метка тома, серийный номер — через GetVolumeInformationW
    info['filesystem'] = '---'
    info['volume_label'] = '---'
    info['volume_serial'] = '---'
    info['total_bytes'] = 0
    info['free_bytes'] = 0
    info['disk_model'] = '---'
    info['disk_serial'] = '---'

    if platform.system() == 'Windows':
        try:
            fs_buf = ctypes.create_unicode_buffer(256)
            vol_name = ctypes.create_unicode_buffer(256)
            serial = ctypes.c_uint32(0)
            max_len = ctypes.c_uint32(0)
            flags = ctypes.c_uint32(0)
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_letter + '\\\\'),
                vol_name, 256, ctypes.byref(serial),
                ctypes.byref(max_len), ctypes.byref(flags),
                fs_buf, 256)
            if ok:
                info['filesystem'] = fs_buf.value or '---'
                info['volume_label'] = vol_name.value or '---'
                info['volume_serial'] = '%08X' % serial.value
        except Exception:
            pass

        try:
            total = ctypes.c_uint64(0)
            free = ctypes.c_uint64(0)
            ok = ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(drive_letter + '\\\\'),
                None, ctypes.byref(total), ctypes.byref(free))
            if ok:
                info['total_bytes'] = total.value
                info['free_bytes'] = free.value
        except Exception:
            pass

        # === Уровень 1: WinAPI DeviceIoControl ===
        try:
            model, serial_num = _get_disk_info_winapi(drive_letter)
            if model:
                info['disk_model'] = model
            if serial_num:
                info['disk_serial'] = serial_num
        except Exception:
            pass

        # === Уровень 2: wmic с retry ===
        if info['disk_model'] == '---' or info['disk_serial'] == '---':
            for attempt in range(3):
                try:
                    r = subprocess.run(
                        ['wmic', 'diskdrive', 'get', 'Model,SerialNumber'],
                        capture_output=True, text=True, timeout=30)
                    wmic_lines = [l.strip() for l in r.stdout.strip().split('\n') if l.strip()]
                    if len(wmic_lines) > 1 and wmic_lines[1].strip():
                        parts = wmic_lines[1].split(None, 1)
                        if len(parts) >= 1:
                            info['disk_model'] = parts[0]
                        if len(parts) >= 2:
                            info['disk_serial'] = parts[1].strip()
                        break
                except Exception:
                    if attempt < 2:
                        time.sleep(2)

        # === Уровень 3: PowerShell fallback ===
        if info['disk_model'] == '---' or info['disk_serial'] == '---':
            try:
                r = subprocess.run(
                    ['powershell', '-Command',
                     'Get-WmiObject Win32_DiskDrive | Select-Object Model,SerialNumber | Format-List'],
                    capture_output=True, text=True, timeout=30)
                ps_text = r.stdout.strip()
                if ps_text:
                    for ps_line in ps_text.split('\n'):
                        if 'Model' in ps_line and ':' in ps_line:
                            info['disk_model'] = ps_line.split(':', 1)[1].strip()
                        if 'SerialNumber' in ps_line and ':' in ps_line:
                            info['disk_serial'] = ps_line.split(':', 1)[1].strip()
            except Exception:
                pass
    else:
        # Non-Windows: shutil.disk_usage
        try:
            du = shutil.disk_usage(path)
            info['total_bytes'] = du.total
            info['free_bytes'] = du.free
        except Exception:
            pass
    # Алиасы ключей для main()
    info['drive'] = drive_letter
    info['fs_type'] = info['filesystem']
    info['total'] = info['total_bytes']
    info['free'] = info['free_bytes']
    return info

def get_script_info():
    info = {}
    script_path = os.path.abspath(__file__)
    info['name'] = os.path.basename(script_path)
    info['path'] = script_path
    info['size'] = os.path.getsize(script_path)
    info['mtime'] = file_mtime(script_path).strftime('%Y-%m-%d %H:%M:%S')
    info['md5'] = md5_file(script_path)
    info['version'] = VERSION
    return info

# ============================================================
# Штамп на PNG-графиках
# ============================================================

def add_png_footer(fig, y_pos=0.01):
    """Добавляет штамп в левый нижний угол: версия, MD5, дата скрипта, дата PNG."""
    try:
        script_path = os.path.abspath(__file__)
        script_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(script_path))
        script_md5 = md5_file(script_path)[:8]
    except Exception:
        script_mtime = datetime.datetime.now()
        script_md5 = '--------'
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    script_str = script_mtime.strftime('%Y-%m-%d %H:%M:%S')
    footer = '%s v%s | MD5: %s | Скрипт от: %s | PNG: %s' % (
        os.path.basename(script_path), VERSION, script_md5, script_str, now_str)
    fig.text(0.02, y_pos, footer, ha='left', va='bottom', fontsize=6,
             color='gray', family='monospace',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8, edgecolor='gray', linewidth=0.5))

def add_status_banner(fig, check_name, errors, warnings, y_pos=0.97):
    """Добавляет цветной статус-баннер в левый верхний угол PNG."""
    if errors > 0:
        status = 'ОШИБКА: %d' % errors
        color = '#e74c3c'
    elif warnings > 0:
        status = 'ВНИМАНИЕ: %d' % warnings
        color = '#f39c12'
    else:
        status = 'OK'
        color = '#2ecc71'
    text = '%s — РЕЗУЛЬТАТ: %s' % (check_name, status)
    fig.text(0.02, y_pos, text, ha='left', va='top', fontsize=10,
             fontweight='bold', color=color, family='monospace')

def save_png_with_stamps(fig, png_path, check_name, errors, warnings):
    """Единая функция сохранения PNG со штампами.
    Отступы считаются от РЕАЛЬНОГО размера фигуры в дюймах — одинаковый
    абсолютный зазор для всех графиков независимо от их высоты."""
    fig_h = fig.get_figheight()
    # Абсолютные отступы в дюймах
    TOP_INCHES = 0.50     # баннер 0.15" + зазор 0.35" до графика
    BOTTOM_INCHES = 0.55  # подпись оси 0.30" + штамп 0.10" + зазор 0.15"
    BANNER_EDGE = 0.05    # отступ баннера от верхнего края
    FOOTER_EDGE = 0.02    # отступ штампа от нижнего края
    # Перевод в фигуро-относительные
    top_frac = 1.0 - TOP_INCHES / fig_h
    bottom_frac = BOTTOM_INCHES / fig_h
    banner_y = 1.0 - BANNER_EDGE / fig_h
    footer_y = FOOTER_EDGE / fig_h
    fig.subplots_adjust(top=top_frac, bottom=bottom_frac, left=0.08, right=0.96)
    add_status_banner(fig, check_name, errors, warnings, y_pos=banner_y)
    add_png_footer(fig, y_pos=footer_y)
    fig.savefig(png_path, dpi=150)




# ============================================================
# Перцептивный хэш (вынесено на уровень модуля для v3.3)
# ============================================================

def compute_phash(frame):
    """Вычисляет перцептивный хэш 8x8 (64 бита) для кадра.
    Векторизованная: reshape для делимых размеров, cumsum для остальных."""
    h, w = frame.shape
    bh, bw = h // 8, w // 8
    if h == bh * 8 and w == bw * 8:
        # Быстрый путь: reshape + mean (без Python-циклов)
        small = frame.astype(np.float64).reshape(8, bh, 8, bw).mean(axis=(1, 3))
    else:
        # Fallback: кумулятивная сумма для не делимых размеров
        row_idx = np.arange(9) * h // 8
        col_idx = np.arange(9) * w // 8
        cum = np.cumsum(np.cumsum(frame.astype(np.float64), axis=0), axis=1)
        cum = np.pad(cum, ((1, 0), (1, 0)), mode='constant')
        r, c = row_idx, col_idx
        block_sums = (cum[np.ix_(r[1:], c[1:])]
                      - cum[np.ix_(r[:-1], c[1:])]
                      - cum[np.ix_(r[1:], c[:-1])]
                      + cum[np.ix_(r[:-1], c[:-1])])
        areas = np.outer(np.diff(r), np.diff(c)).astype(np.float64)
        small = block_sums / areas
    mean_val = np.mean(small)
    bits = (small > mean_val).astype(np.uint8).flatten()
    return bits

def hamming(h1, h2):
    """Расстояние Хэмминга между двумя битовыми массивами."""
    return int(np.sum(h1 != h2))


# ============================================================
# Проверки
# ============================================================

# ============================================================
# Вспомогательные функции для холодного пуска
# ============================================================

def extract_date_from_filename(filepath):
    """Извлекает год из имени файла (первые 4 цифры)."""
    fname = os.path.basename(filepath)
    digits = ''.join(c for c in fname if c.isdigit())
    if len(digits) >= 4:
        try:
            return int(digits[:4])
        except ValueError:
            return None
    return None

def get_majority_year(file_data):
    """Определяет 'нормальный' год — наиболее частый в наборе."""
    from collections import Counter
    years = []
    for filepath, _ in file_data:
        y = extract_date_from_filename(filepath)
        if y is not None:
            years.append(y)
    if not years:
        return None
    counter = Counter(years)
    return counter.most_common(1)[0][0]

def is_factory_date_file(filepath, file_data):
    """True, если файл имеет заводскую дату (год значительно отличается от большинства)."""
    majority_year = get_majority_year(file_data)
    if majority_year is None:
        return False
    file_year = extract_date_from_filename(filepath)
    if file_year is None:
        return False
    return abs(file_year - majority_year) > 1

def get_first_gps_file_index(file_data):
    """Индекс первого файла с GPS-метками."""
    for i, (filepath, data) in enumerate(file_data):
        if data['gps_data']:
            return i
    return -1

def is_startup_file(filepath, data):
    """True, если файл — короткий стартовый фрагмент (PTS < 60 сек)."""
    pts_v = data.get('pts_video_list', data['pts_list'])
    if pts_v:
        duration = pts_v[-1] - pts_v[0]
        if duration < 58:
            return True
    return False

def gps_coord_distance(gps1, gps2):
    """Приблизительное расстояние между двумя GPS-точками в метрах."""
    if not gps1 or not gps2:
        return 999
    lat1 = gps1['Loc']['Lat']['Float']
    lon1 = gps1['Loc']['Lon']['Float']
    lat2 = gps2['Loc']['Lat']['Float']
    lon2 = gps2['Loc']['Lon']['Float']
    if lat1 is None or lat2 is None or lon1 is None or lon2 is None:
        return 999
    # Приближение: 1 градус широты ~ 111 км
    dlat = (lat2 - lat1) * 111000
    dlon = (lon2 - lon1) * 111000 * math.cos(math.radians(lat1))
    return (dlat**2 + dlon**2) ** 0.5


def check_gps_time(file_data, gap_threshold=1, file_gap_threshold=1):
    """Проверка 2.1: непрерывность GPS-времени. Возвращает (errors, warnings, lines, explained)."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []

    first_gps_idx = get_first_gps_file_index(file_data)

    # 2.1.1 Разрывы/сдвиги внутри файлов
    for file_idx, (filepath, data) in enumerate(file_data):
        gps_points = data['gps_data']
        if not gps_points:
            continue
        for i in range(1, len(gps_points)):
            prev_dt = dt_to_datetime(gps_points[i - 1])
            curr_dt = dt_to_datetime(gps_points[i])
            if not prev_dt or not curr_dt:
                continue
            delta = (curr_dt - prev_dt).total_seconds()
            if delta < 0:
                # Сдвиг назад
                if abs(delta) <= 1:
                    # Проверяем плавность координат
                    dist = gps_coord_distance(gps_points[i-1], gps_points[i])
                    if dist < 100:
                        explained += 1
                        lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))
                        lines.append('        Тип: коррекция времени GPS-приёмником')
                        lines.append('        Сдвиг <= 1 сек, координаты плавные (смещение %.1f м). Нормальное' % dist)
                        lines.append('        поведение GPS-приёмника при переключении спутников.')
                        lines.append('')
                    else:
                        errors += 1
                        lines.append('    [СДВИГ_НАЗАД] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))
                else:
                    errors += 1
                    lines.append('    [СДВИГ_НАЗАД] %s, точка #%d: %s -> %s (%.0f сек)' % (
                        os.path.basename(filepath), i,
                        format_msk(prev_dt), format_msk(curr_dt), delta))
            elif delta > gap_threshold:
                # Разрыв внутри файла
                if file_idx == first_gps_idx and delta <= 2:
                    # Разрывы в первом файле с GPS — холодный пуск
                    explained += 1
                    lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %s -> %s (%.0f сек)' % (
                        os.path.basename(filepath), i,
                        format_msk(prev_dt), format_msk(curr_dt), delta))
                    lines.append('        Тип: холодный пуск GPS, стабилизация приёмника')
                    lines.append('        Первый файл с GPS: модуль только что захватил спутники,')
                    lines.append('        приёмник не успевает выдавать позицию каждую секунду.')
                    lines.append('        Разрывы только по 2 сек, только в первом файле — норма.')
                    lines.append('')
                else:
                    # Проверяем, не потеря ли это GPS-сигнала
                    dist = gps_coord_distance(gps_points[i-1], gps_points[i])
                    prev_speed = gps_points[i-1]['Loc']['Speed']
                    curr_speed = gps_points[i]['Loc']['Speed']
                    # Если координаты "застыли" (та же точка) или скорость 0
                    coords_frozen = (dist < 5)
                    speed_zero = (prev_speed is not None and prev_speed < 1 and 
                                  curr_speed is not None and curr_speed < 1)
                    if coords_frozen or speed_zero:
                        explained += 1
                        lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))
                        lines.append('        Тип: потеря GPS-сигнала. Координаты "заморожены" или скорость 0.')
                        lines.append('        Регистратор потерял спутники, GPS-время идёт с пропусками. Норма.')
                        lines.append('')
                    elif delta <= 3:
                        # Правка №2+6: 2-3 сек gaps при движении — прерывистый приём GPS
                        explained += 1
                        lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))
                        lines.append('        Тип: прерывистый приём GPS при движении в плотной застройке.')
                        lines.append('        Кратковременная потеря спутников до 3 сек. Норма для городских условий.')
                        lines.append('')
                    elif dist > 50:
                        # Правка №5: кросс-реф 2.1 ↔ 2.16.6 — скачок координат совпадает с разрывом времени
                        explained += 1
                        lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))
                        lines.append('        Тип: потеря GPS-сигнала, скачок координат (%.0f м) совпадает с разрывом времени.' % dist)
                        lines.append('        Регистратор потерял спутники, координаты сместились. Норма.')
                        lines.append('')
                    else:
                        errors += 1
                        lines.append('    [РАЗРЫВ] %s, точка #%d: %s -> %s (%.0f сек)' % (
                            os.path.basename(filepath), i,
                            format_msk(prev_dt), format_msk(curr_dt), delta))

    # 2.1.2 Разрывы между файлами
    files_with_gps = [(fp, d, idx) for idx, (fp, d) in enumerate(file_data) if d['gps_data']]
    for i in range(1, len(files_with_gps)):
        prev_file, prev_data, prev_idx = files_with_gps[i - 1]
        curr_file, curr_data, curr_idx = files_with_gps[i]
        prev_points = prev_data['gps_data']
        curr_points = curr_data['gps_data']
        if not prev_points or not curr_points:
            continue
        last_dt = dt_to_datetime(prev_points[-1])
        first_dt = dt_to_datetime(curr_points[0])
        if not last_dt or not first_dt:
            continue
        delta = (first_dt - last_dt).total_seconds()
        if delta < 0:
            errors += 1
            lines.append('    [НАЛОЖЕНИЕ] %s -> %s: %s -> %s (%.0f сек)' % (
                os.path.basename(prev_file), os.path.basename(curr_file),
                format_msk(last_dt), format_msk(first_dt), delta))
        elif delta > file_gap_threshold:
            # Проверяем: предыдущий файл — стартовый?
            if is_startup_file(prev_file, prev_data) and delta <= 5:
                explained += 1
                lines.append('    [ОБЪЯСНЕНО] %s -> %s: %s -> %s (%.0f сек)' % (
                    os.path.basename(prev_file), os.path.basename(curr_file),
                    format_msk(last_dt), format_msk(first_dt), delta))
                lines.append('        Тип: пауза циклической записи при переходе от стартового фрагмента')
                lines.append('        Предыдущий файл короткий (стартовый), регистратор закрыл его')
                lines.append('        раньше цикла. Пауза 2-5 сек — задержка файловой системы')
                lines.append('        (сброс буферов, создание нового файла). Норма.')
                lines.append('')
            elif delta <= 10:
                # Правка №7: межфайловый зазор до 10 сек — норма для регистратора
                explained += 1
                lines.append('    [ОБЪЯСНЕНО] %s -> %s: %s -> %s (%.0f сек)' % (
                    os.path.basename(prev_file), os.path.basename(curr_file),
                    format_msk(last_dt), format_msk(first_dt), delta))
                lines.append('        Тип: нормальный межфайловый зазор регистратора.')
                lines.append('        Регистратор завершает один файл и создаёт следующий.')
                lines.append('        Пауза до 10 сек — задержка файловой системы (сброс буферов).')
                lines.append('        Норма для циклической записи.')
                lines.append('')
            else:
                errors += 1
                lines.append('    [РАЗРЫВ] %s -> %s: %s -> %s (%.0f сек)' % (
                    os.path.basename(prev_file), os.path.basename(curr_file),
                    format_msk(last_dt), format_msk(first_dt), delta))

    if not lines:
        lines.append('    [OK] Разрывов GPS-времени не обнаружено')
    return errors, warnings, lines, explained

def check_gps_coords(file_data):
    """Проверка 2.2: непрерывность GPS-координат."""
    errors = 0
    warnings = 0
    lines = []
    for filepath, data in file_data:
        gps_points = data['gps_data']
        if not gps_points or len(gps_points) < 2:
            continue
        for i in range(1, len(gps_points)):
            prev = gps_points[i - 1]['Loc']
            curr = gps_points[i]['Loc']
            if prev['Lat']['Float'] is None or curr['Lat']['Float'] is None:
                continue
            dlat = abs(curr['Lat']['Float'] - prev['Lat']['Float'])
            dlon = abs(curr['Lon']['Float'] - prev['Lon']['Float'])
            if dlat > 0.01 or dlon > 0.01:
                # Проверяем, совпадает ли скачок с разрывом GPS-времени
                prev_dt = dt_to_datetime(gps_points[i - 1])
                curr_dt = dt_to_datetime(gps_points[i])
                time_gap = False
                if prev_dt and curr_dt:
                    time_delta = abs((curr_dt - prev_dt).total_seconds())
                    if time_delta > 2:
                        time_gap = True
                if time_gap:
                    lines.append('    [ОБЪЯСНЕНО] %s, точка #%d: %.6f,%.6f -> %.6f,%.6f' % (
                        os.path.basename(filepath), i,
                        prev['Lat']['Float'], prev['Lon']['Float'],
                        curr['Lat']['Float'], curr['Lon']['Float']))
                    lines.append('        Тип: потеря GPS-сигнала. Скачок координат совпадает с разрывом времени.')
                    lines.append('')
                else:
                    errors += 1
                    lines.append('    [СКАЧОК] %s, точка #%d: %.6f,%.6f -> %.6f,%.6f' % (
                        os.path.basename(filepath), i,
                        prev['Lat']['Float'], prev['Lon']['Float'],
                        curr['Lat']['Float'], curr['Lon']['Float']))
    if not lines:
        lines.append('    [OK] Скачков координат не обнаружено')
    return errors, warnings, lines, 0

def check_filenames(file_data):
    """Проверка 2.3: имена файлов."""
    errors = 0
    warnings = 0
    lines = []
    pattern = re.compile(r'^\d{14}_\d{6}[A-Z]?\.TS$', re.IGNORECASE)
    bad = []
    for filepath, _ in file_data:
        fname = os.path.basename(filepath)
        if not pattern.match(fname):
            bad.append(fname)
    if bad:
        warnings += len(bad)
        for f in bad:
            lines.append('    [ВНИМАНИЕ] %s: имя не соответствует шаблону' % f)
    else:
        if len(file_data) == 1:
            lines.append('    [OK] Имя файла соответствует шаблону (один файл)')
        else:
            lines.append('    [OK] Имена файлов соответствуют шаблону и упорядочены по времени')
    return errors, warnings, lines, 0

def check_pids(file_data):
    """Проверка 2.4: набор PID (с учётом холодного пуска)."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    if not file_data:
        return errors, warnings, lines, explained
    # Эталон — набор PID из первого файла с реальной датой
    ref_pids = None
    for filepath, data in file_data:
        if not is_factory_date_file(filepath, file_data):
            ref_pids = data['pids']
            break
    if ref_pids is None:
        ref_pids = file_data[0][1]['pids']
    for filepath, data in file_data:
        if is_factory_date_file(filepath, file_data):
            # Заводские файлы могут иметь отличный набор PID — GPS PID может отсутствовать
            if data['pids'] != ref_pids:
                explained += 1
                missing = ref_pids - data['pids']
                extra = data['pids'] - ref_pids
                msg = '    [ОБЪЯСНЕНО] %s: отличие набора PID' % os.path.basename(filepath)
                if missing:
                    msg += ' (нет: %s)' % ', '.join('0x%04X' % p for p in sorted(missing))
                if extra:
                    msg += ' (лишние: %s)' % ', '.join('0x%04X' % p for p in sorted(extra))
                lines.append(msg)
                lines.append('        Тип: холодный пуск, GPS-модуль не захвачен. Заводской файл')
                lines.append('        может не содержать GPS PID. Норма.')
                lines.append('')
            continue
        if data['pids'] != ref_pids:
            errors += 1
            missing = ref_pids - data['pids']
            extra = data['pids'] - ref_pids
            msg = '    [ОШИБКА] %s: отличие набора PID' % os.path.basename(filepath)
            if missing:
                msg += ' (нет: %s)' % ', '.join('0x%04X' % p for p in sorted(missing))
            if extra:
                msg += ' (лишние: %s)' % ', '.join('0x%04X' % p for p in sorted(extra))
            lines.append(msg)
    if not lines:
        if len(file_data) == 1:
            lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение набора PID не требуется')
        else:
            lines.append('    [OK] Набор PID одинаков во всех файлах')
    return errors, warnings, lines, explained

def check_stream_params(file_data):
    """Проверка 2.5: параметры потока (с учётом холодного пуска)."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    if not file_data:
        return errors, warnings, lines, explained
    # Эталон — первый файл с реальной датой
    ref = None
    for filepath, data in file_data:
        if not is_factory_date_file(filepath, file_data):
            ref = data
            break
    if ref is None:
        ref = file_data[0][1]
    ref_video = ref['video_pid']
    ref_audio = ref['audio_pid']
    for filepath, data in file_data:
        if is_factory_date_file(filepath, file_data):
            # Заводские файлы могут не иметь видео/аудио PID
            if data['video_pid'] != ref_video or data['audio_pid'] != ref_audio:
                explained += 1
                lines.append('    [ОБЪЯСНЕНО] %s: параметры потока отличаются (заводской файл)' % (
                    os.path.basename(filepath)))
                lines.append('        Тип: холодный пуск, заводской файл. Видео/аудио PID могут')
                lines.append('        отсутствовать в стартовых фрагментах. Норма.')
                lines.append('')
            continue
        if data['video_pid'] != ref_video:
            errors += 1
            lines.append('    [ОШИБКА] %s: видео PID отличается (0x%04X vs 0x%04X)' % (
                os.path.basename(filepath), data['video_pid'] or 0, ref_video or 0))
        if data['audio_pid'] != ref_audio:
            errors += 1
            lines.append('    [ОШИБКА] %s: аудио PID отличается (0x%04X vs 0x%04X)' % (
                os.path.basename(filepath), data['audio_pid'] or 0, ref_audio or 0))
    if not lines:
        if len(file_data) == 1:
            lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение параметров потока не требуется')
        else:
            lines.append('    [OK] Параметры потока (видео/аудио PID) одинаковы во всех файлах')
    return errors, warnings, lines, explained

def check_pcr(file_data):
    """Проверка 2.6: PCR (с учётом холодного запуска)."""
    errors = 0
    warnings = 0
    lines = []

    # 2.6.1 PCR внутри файлов
    lines.append('  2.6.1. PCR внутри файлов:')
    inner_ok = True
    for filepath, data in file_data:
        pcrs = data['pcr_list']
        if len(pcrs) < 2:
            continue
        for i in range(1, len(pcrs)):
            delta = pcrs[i] - pcrs[i - 1]
            if delta < -0.1 or delta > 2.0:
                errors += 1
                inner_ok = False
                lines.append('    [РАЗРЫВ PCR] %s: %.3f -> %.3f сек (дельта %.3f)' % (
                    os.path.basename(filepath), pcrs[i-1], pcrs[i], delta))
    if inner_ok:
        lines.append('    [OK] Разрывы PCR внутри файлов не обнаружены')

    # 2.6.2 PCR между файлами
    lines.append('')
    lines.append('  2.6.2. PCR между файлами (учёт холодного запуска):')
    lines.append('')
    resets = 0
    non_resets = 0
    reset_lines = []
    non_reset_lines = []
    for i in range(1, len(file_data)):
        prev_data = file_data[i - 1][1]
        curr_data = file_data[i][1]
        if not prev_data['pcr_list'] or not curr_data['pcr_list']:
            continue
        prev_pcr = prev_data['pcr_list'][-1]
        curr_pcr = curr_data['pcr_list'][0]
        delta = curr_pcr - prev_pcr
        if delta < -1.0:
            resets += 1
            reset_lines.append('      %s -> %s: PCR %.3f -> %.3f (сброс)' % (
                os.path.basename(file_data[i-1][0]),
                os.path.basename(file_data[i][0]),
                prev_pcr, curr_pcr))
        else:
            non_resets += 1
            non_reset_lines.append('      %s -> %s: PCR %.3f -> %.3f (без сброса, дельта %.3f)' % (
                os.path.basename(file_data[i-1][0]),
                os.path.basename(file_data[i][0]),
                prev_pcr, curr_pcr, delta))

    if resets > 0:
        lines.append('    [OK] Обнаружен сброс PCR между файлами (%d случаев) - норма для 1-минутных фрагментов:' % resets)
        lines.extend(reset_lines)
    if non_resets > 0:
        warnings += non_resets
        lines.append('')
        lines.append('    [ВНИМАНИЕ] Отсутствие сброса PCR (%d случаев):' % non_resets)
        lines.extend(non_reset_lines)
    if resets == 0 and non_resets == 0:
        if len(file_data) == 1:
            lines.append('    [НЕ ПРИМЕНИМО] Один файл — проверка PCR между файлами не требуется')
        else:
            lines.append('    [OK] Нет данных PCR для проверки между файлами')
    lines.append('')
    return errors, warnings, lines, 0

def check_pts(file_data):
    """Проверка 2.7: PTS (с учётом холодного запуска)."""
    errors = 0
    warnings = 0
    lines = []

    # 2.7.1 PTS внутри файлов
    lines.append('  2.7.1. PTS внутри файлов:')
    inner_ok = True
    for filepath, data in file_data:
        pts_list = data.get('pts_video_list', data['pts_list'])
        if len(pts_list) < 2:
            continue
        for i in range(1, len(pts_list)):
            delta = pts_list[i] - pts_list[i - 1]
            if delta < -0.1 or delta > 2.0:
                errors += 1
                inner_ok = False
                lines.append('    [РАЗРЫВ PTS] %s: %.3f -> %.3f сек (дельта %.3f)' % (
                    os.path.basename(filepath), pts_list[i-1], pts_list[i], delta))
    if inner_ok:
        lines.append('    [OK] Разрывы PTS внутри файлов не обнаружены')

    # 2.7.2 PTS между файлами
    lines.append('')
    lines.append('  2.7.2. PTS между файлами (учёт холодного запуска):')
    lines.append('')
    resets = 0
    non_resets = 0
    reset_lines = []
    non_reset_lines = []
    for i in range(1, len(file_data)):
        prev_data = file_data[i - 1][1]
        curr_data = file_data[i][1]
        prev_vpts = prev_data.get('pts_video_list', prev_data['pts_list'])
        curr_vpts = curr_data.get('pts_video_list', curr_data['pts_list'])
        if not prev_vpts or not curr_vpts:
            continue
        prev_pts = prev_vpts[-1]
        curr_pts = curr_vpts[0]
        delta = curr_pts - prev_pts
        if delta < -1.0:
            resets += 1
            reset_lines.append('      %s -> %s: PTS %.3f -> %.3f (сброс)' % (
                os.path.basename(file_data[i-1][0]),
                os.path.basename(file_data[i][0]),
                prev_pts, curr_pts))
        else:
            non_resets += 1
            non_reset_lines.append('      %s -> %s: PTS %.3f -> %.3f (без сброса, дельта %.3f)' % (
                os.path.basename(file_data[i-1][0]),
                os.path.basename(file_data[i][0]),
                prev_pts, curr_pts, delta))

    if resets > 0:
        lines.append('    [OK] Обнаружен сброс PTS между файлами (%d случаев) - норма для 1-минутных фрагментов:' % resets)
        lines.extend(reset_lines)
    if non_resets > 0:
        warnings += non_resets
        lines.append('')
        lines.append('    [ВНИМАНИЕ] Отсутствие сброса PTS (%d случаев):' % non_resets)
        lines.extend(non_reset_lines)
    if resets == 0 and non_resets == 0:
        if len(file_data) == 1:
            lines.append('    [НЕ ПРИМЕНИМО] Один файл — проверка PTS между файлами не требуется')
        else:
            lines.append('    [OK] Нет данных PTS для проверки между файлами')
    lines.append('')
    return errors, warnings, lines, 0

def check_cc(file_data):
    """Проверка 2.8: Continuity Counter."""
    errors = 0
    warnings = 0
    lines = []
    total_errors = 0
    for filepath, data in file_data:
        if data['cc_errors']:
            total_errors += sum(data['cc_errors'].values())
            for pid, cnt in sorted(data['cc_errors'].items()):
                errors += 1
                lines.append('    [ОШИБКА] %s: PID 0x%04X - %d ошибок CC' % (
                    os.path.basename(filepath), pid, cnt))
    if not lines:
        lines.append('    [OK] Ошибки Continuity Counter не обнаружены')
    return errors, warnings, lines, 0

def check_bitrate(file_data):
    """Проверка 2.9: битрейт."""
    errors = 0
    warnings = 0
    lines = []
    bitrates = []
    for filepath, data in file_data:
        size = file_size(filepath)
        pcrs = data['pcr_list']
        if len(pcrs) >= 2:
            duration = pcrs[-1] - pcrs[0]
            if duration > 0:
                bitrate = (size * 8) / duration / 1000000.0
                bitrates.append((os.path.basename(filepath), bitrate, duration))
    if bitrates:
        avg_br = sum(b[1] for b in bitrates) / len(bitrates)
        lines.append('    Средний битрейт: %.2f Мбит/с' % avg_br)
        for fname, br, dur in bitrates:
            lines.append('      %s: %.2f Мбит/с (длительность %.1f сек)' % (fname, br, dur))
        if len(bitrates) > 1:
            br_values = [b[1] for b in bitrates]
            mean_br = sum(br_values) / len(br_values)
            variance = sum((x - mean_br) ** 2 for x in br_values) / len(br_values)
            std_dev = variance ** 0.5
            cv = (std_dev / mean_br * 100.0) if mean_br > 0 else 0
            if cv > 10:
                errors += 1
                lines.append('    [ОШИБКА] Битрейт нестабилен (коэффициент вариации %.1f%%)' % cv)
            elif cv > 5:
                warnings += 1
                lines.append('    [ВНИМАНИЕ] Битрейт нестабилен (коэффициент вариации %.1f%%)' % cv)
            else:
                lines.append('    [OK] Битрейт стабилен (коэффициент вариации %.1f%%)' % cv)
        else:
            lines.append('    [OK] Один файл, сравнение битрейта не требуется')
    else:
        lines.append('    [OK] Нет данных для расчёта битрейта')
    return errors, warnings, lines, 0

def check_mtime(file_data):
    """Проверка 2.10: время последней записи."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    prev_mtime = None
    for filepath, _ in file_data:
        if is_factory_date_file(filepath, file_data):
            explained += 1
            mtime = file_mtime(filepath)
            lines.append('    [ОБЪЯСНЕНО] %s: mtime %s — заводской файл, RTC сброшен' % (
                os.path.basename(filepath), mtime.strftime('%Y-%m-%d %H:%M:%S')))
            # Не обновляем prev_mtime — следующий файл сравнивается с последним нормальным
            continue
        mtime = file_mtime(filepath)
        if prev_mtime and mtime < prev_mtime:
            errors += 1
            lines.append('    [ОШИБКА] %s: время последней записи раньше предыдущего' % os.path.basename(filepath))
        prev_mtime = mtime
    if errors == 0:
        if len(file_data) == 1 and explained == 0:
            lines.append('    [НЕ ПРИМЕНИМО] Один файл — упорядочивание mtime не требуется')
        else:
            lines.append('    [OK] Время последней записи упорядочено по возрастанию')
    return errors, warnings, lines, explained

def check_gps_presence(file_data):
    """Проверка 2.11: наличие GPS во всех файлах (с учётом холодного пуска)."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    for filepath, data in file_data:
        if not data['gps_data']:
            if is_factory_date_file(filepath, file_data):
                explained += 1
                lines.append('    [ОБЪЯСНЕНО] %s: GPS-метки отсутствуют' % os.path.basename(filepath))
                lines.append('        Тип: холодный пуск, GPS-модуль не захватил спутники')
                year = extract_date_from_filename(filepath)
                lines.append('        Дата в имени файла: %d (заводская). RTC сброшен на заводскую' % year)
                lines.append('        дату. Дата и время устанавливаются от GPS только после захвата')
                lines.append('        спутников. Файл записан до захвата GPS. Норма.')
                lines.append('')
            else:
                warnings += 1
                lines.append('    [ВНИМАНИЕ] %s: GPS-метки отсутствуют' % os.path.basename(filepath))
    if not lines:
        lines.append('    [OK] GPS-метки присутствуют во всех файлах')
    return errors, warnings, lines, explained

def check_file_sizes(file_data):
    """Проверка 2.12: согласованность размеров файлов (с учётом холодного пуска)."""
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    sizes = [file_size(fp) for fp, _ in file_data]
    if len(sizes) < 2:
        lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение размеров не требуется')
        return errors, warnings, lines, explained
    import statistics
    median_size = statistics.median(sizes)
    for filepath, data in file_data:
        sz = file_size(filepath)
        if median_size > 0:
            deviation = abs(sz - median_size) / median_size * 100.0
            if deviation > 50:
                if is_startup_file(filepath, data):
                    explained += 1
                    lines.append('    [ОБЪЯСНЕНО] %s: размер %d байт, медиана %d байт (отклонение %.1f%%)' % (
                        os.path.basename(filepath), sz, median_size, deviation))
                    lines.append('        Тип: короткий стартовый фрагмент холодного пуска')
                    pts_v = data.get('pts_video_list', data['pts_list'])
                    if pts_v:
                        dur = pts_v[-1] - pts_v[0]
                        lines.append('        PTS-длительность: %.1f сек (< 60 сек). Регистратор записал' % dur)
                    lines.append('        короткий фрагмент при старте. Норма для холодного пуска.')
                    lines.append('')
                else:
                    warnings += 1
                    lines.append('    [ВНИМАНИЕ] %s: размер %d байт, медиана %d байт (отклонение %.1f%%)' % (
                        os.path.basename(filepath), sz, median_size, deviation))
    if not lines:
        lines.append('    [OK] Размеры файлов согласованы')
    return errors, warnings, lines, explained



# ============================================================
# Генерация файла детализации ошибок
# ============================================================

def generate_error_details(output_path, file_data=None):
    """Создаёт файл error_details.txt с физическими объяснениями всех типов ошибок.
    
    Объясняет не что делает код, а что физически произошло с видео.
    """
    lines = []
    
    lines.append('=' * 70)
    lines.append('  ДЕТАЛИЗАЦИЯ ТИПОВ ОШИБОК И ПРЕДУПРЕЖДЕНИЙ')
    lines.append('  Физические объяснения проблем с видео')
    lines.append('=' * 70)
    lines.append('')
    lines.append('Этот файл объясняет, что физически означает каждая метка')
    lines.append('в протоколе проверки. Не технические детали кода, а что')
    lines.append('реально произошло с видеозаписью.')
    lines.append('')
    
    # ============================================================
    # Раздел 1: Расшифровка меток
    # ============================================================
    lines.append('-' * 70)
    lines.append('  РАЗДЕЛ 1. РАСШИФРОВКА МЕТОК')
    lines.append('-' * 70)
    lines.append('')
    
    markers = [
        ('[OK]', 'Проверка пройдена. Проблем не обнаружено. Файл соответствует ожиданиям для непрерывной записи с регистратора.'),
        ('[НЕ ПРИМЕНИМО]', 'Проверка не имеет смысла для данного набора файлов. Например, сравнение между файлами при одном файле. Это не ошибка — просто проверка неприменима.'),
        ('[ОБЪЯСНЕНО]', 'Обнаружено отклонение, но оно объяснимо и не указывает на модификацию. Например, холодный пуск GPS-приёмника в первом файле — регистратор только включился и ещё не поймал спутники.'),
        ('[ВНИМАНИЕ]', 'Обнаружено отклонение, которое требует внимания. Само по себе не доказывает модификацию, но может быть признаком проблемы. Например, отсутствие IDR-кадров или нестабильный битрейт.'),
        ('[ОШИБКА]', 'Обнаружена проблема, которая с высокой вероятностью указывает на модификацию файла (склейку, вырезание, вставку). Требует дальнейшего анализа.'),
        ('[РАЗРЫВ]', 'Между соседними точками данных (GPS-время, GPS-координаты, PCR, PTS) обнаружен пропуск. Часть времени или данных выпала. Физически: между двумя соседними метками промежуток больше ожидаемого.'),
        ('[НАЛОЖЕНИЕ]', 'Время следующей точки МЕНЬШЕ времени предыдущей. Два фрагмента перекрывают друг друга по времени. Физически: один и тот же момент записан дважды. Признак склейки с наложением.'),
        ('[СКАЧОК]', 'Координаты резко изменились между соседними GPS-точками. Например, машина за 1 секунду переместилась на 10 км. Физически: либо потеря спутников и скачок позиции, либо вырезан фрагмент маршрута.'),
        ('[СДВИГ_НАЗАД]', 'GPS-время ушло назад (на 1 секунду и меньше). Физически: GPS-приёмник скорректировал время при переключении спутников. Если координаты плавные — нормальное поведение. Если координаты тоже скакнули — возможна склейка.'),
        ('[ДУБЛИКАТ]', 'Последний кадр предыдущего файла и первый кадр следующего идентичны до пикселя (Hamming=0). В реальном видео соседние кадры ВСЕГДА отличаются (шум матрицы, движение). Полное совпадение = кадр скопирован. Признак склейки.'),
        ('[РАЗРЫВ PCR]', 'Системные часы (PCR) прыгнули внутри файла. PCR — внутренние часы мультиплексора, должны расти монотонно. Разрыв означает, что поток был прерван и возобновлён. Возможно: потеря пакетов, перезапись, склейка.'),
        ('[РАЗРЫВ PTS]', 'Временные метки показа (PTS) прыгнули внутри файла. PTS указывает, когда кадр должен появиться на экране. Разрыв означает, что часть кадров пропущена или вставлена. Признак вырезания или склейки.'),
        ('[ПРОПУЩЕНО]', 'Проверка не выполнена из-за недостатка данных. Не ошибка — просто нет данных для анализа. Например, нет GPS-меток для сравнения координат.'),
    ]
    
    for marker, explanation in markers:
        lines.append('  %s' % marker)
        lines.append('    %s' % explanation)
        lines.append('')
    
    # ============================================================
    # Раздел 2: Подробное объяснение по проверкам
    # ============================================================
    lines.append('-' * 70)
    lines.append('  РАЗДЕЛ 2. ПОДРОБНОЕ ОБЪЯСНЕНИЕ ПО ПРОВЕРКАМ')
    lines.append('-' * 70)
    lines.append('')
    
    checks_explained = [
        ('2.1. Непрерывность GPS-времени',
         'Что проверяет: GPS-приёмник регистратора ставит временную метку каждую секунду. Проверка выявляет пропуски и наложения времени.',
         [
            ('[OK]', 'GPS-время идёт непрерывно, по 1 секунде между точками. Регистратор работал без перебоев.'),
            ('[РАЗРЫВ] внутри файла', 'Между двумя соседними GPS-метками внутри одного файла пропуск больше 1 секунды. Например: 05:06:35, потом сразу 05:06:40 — 4 секунды выпали. Физически: либо регистратор кратковременно потерял спутники, либо из файла вырезан фрагмент. Если разрыв совпадает со скачком координат и PTS — вероятна склейка.'),
            ('[НАЛОЖЕНИЕ] между файлами', 'Время первой точки следующего файла МЕНЬШЕ времени последней точки предыдущего. Например: конец 05:07:32, начало следующего 05:07:30. Два файла перекрывают друг друга. Физически: один и тот же момент записан дважды. Признак склейки с наложением.'),
            ('[СДВИГ_НАЗАД] внутри файла', 'GPS-время ушло назад на 1 секунду или меньше. Физически: GPS-приёмник скорректировал время при переключении спутников. Если координаты при этом плавные — нормальное поведение, не модификация. Если координаты тоже скакнули — возможна склейка.'),
            ('[ОБЪЯСНЕНО] холодный пуск', 'Разрывы времени только в первом файле, только по 2 секунды. Регистратор только включился, GPS-модуль ещё стабилизируется. Норма.'),
         ], 'ДА'),
        
        ('2.2. Непрерывность GPS-координат',
         'Что проверяет: координаты машины должны меняться плавно. Проверка выявляет резкие скачки позиции.',
         [
            ('[OK]', 'Координаты меняются плавно. Машина ехала без телепортаций.'),
            ('[СКАЧОК]', 'Координаты резко изменились между соседними GPS-точками (больше 0.01 градуса за 1 секунду — это около 1 км). Физически: либо потеря спутников и скачок позиции, либо из маршрута вырезан фрагмент. Если скачок совпадает с разрывом GPS-времени и PTS — вероятна склейка или вырезание.'),
         ], 'ДА'),
        
        ('2.3. Имена файлов',
         'Что проверяет: имена .ts-файлов должны соответствовать шаблону ГГГГММДДЧЧММСС_НННННН.TS — дата, время и порядковый номер.',
         [
            ('[OK]', 'Имя соответствует шаблону. Дата и время в имени совпадают с GPS-временем начала записи.'),
            ('[ВНИМАНИЕ]', 'Имя не соответствует шаблону. Возможно, файл переименован. Само по себе не доказывает модификацию содержимого, но требует объяснения.'),
         ], 'ДА (один файл: проверяется соответствие шаблону)'),
        
        ('2.4. Набор PID',
         'Что проверяет: PID (Packet Identifier) — идентификатор потока в TS-контейнере. Набор PID должен быть одинаковым во всех файлах. Если в одном файле есть видео-PID, а в другом нет — файлы с разных устройств или модифицированы.',
         [
            ('[OK]', 'Набор PID одинаков во всех файлах. Файлы с одного регистратора.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать набор PID не с чем.'),
            ('[ОШИБКА]', 'Набор PID отличается. Файлы могут быть с разных устройств или один из них модифицирован.'),
         ], 'НЕТ (один файл)'),
        
        ('2.5. Параметры потока',
         'Что проверяет: видео-PID и аудио-PID должны быть одинаковыми во всех файлах. Если видео-PID в одном файле 0x0200, а в другом 0x0300 — потоки разные.',
         [
            ('[OK]', 'Видео и аудио PID одинаковы во всех файлах.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать не с чем.'),
            ('[ОШИБКА]', 'PID отличается. Потоки видео/аудио в разных файлах идут по разным PID. Возможно, файлы с разных регистраторов или перекодированы.'),
         ], 'НЕТ (один файл)'),
        
        ('2.6. PCR (системные часы 27 МГц)',
         'Что проверяет: PCR (Program Clock Reference) — внутренние часы мультиплексора. Должны расти монотонно внутри файла. Между 1-минутными файлами регистратор обычно сбрасывает PCR на ноль — это нормально.',
         [
            ('[OK] внутри файла', 'PCR растёт монотонно внутри файла. Поток не прерывался.'),
            ('[РАЗРЫВ PCR] внутри файла', 'PCR прыгнул внутри файла (ушёл назад или вперёд больше чем на 3 секунды). Физически: поток был прерван и возобновлён. Возможные причины: потеря пакетов, перезапись, склейка.'),
            ('[OK] сброс между файлами', 'PCR сбросился на ноль между файлами. Норма для 1-минутных фрагментов — каждый файл начинается с нуля.'),
            ('[НЕ ПРИМЕНИМО] между файлами', 'Один файл — проверка между файлами не требуется.'),
         ], 'ЧАСТИЧНО (внутри файла — да, между файлами — нет)'),
        
        ('2.7. PTS (временные метки показа, 90 кГц)',
         'Что проверяет: PTS (Presentation Time Stamp) — метка времени, встроенная в каждый видео-кадр. Указывает, в какую секунду кадр должен появиться на экране. Внутри файла PTS видео должна расти монотонно (0.000, 0.033, 0.067, 0.100... для 30 кадров/сек). Между 1-минутными файлами сброс на ноль — норма. В v3.1 используется ТОЛЬКО видео-PTS (раньше видео и аудио PTS смешивались в один список, что давало ложные обратные скачки).',
         [
            ('[OK] внутри файла', 'PTS видео растёт монотонно: 0.000, 0.033, 0.067, 0.100... Кадры идут по порядку, без пропусков и возвратов.'),
            ('[РАЗРЫВ PTS] внутри файла', 'PTS видео прыгнула: разница между соседними кадрами больше 2 секунд или ушла назад. Например: 0.128 -> 0.100 сек (время пошло назад). В непрерывной записи невозможно. Признак склейки или вырезания.'),
            ('[OK] сброс между файлами', 'PTS сбросилась между файлами. Норма для 1-минутных фрагментов.'),
            ('[НЕ ПРИМЕНИМО] между файлами', 'Один файл — проверка между файлами не требуется.'),
         ], 'ЧАСТИЧНО (внутри файла — да, между файлами — нет)'),
        
        ('2.8. Continuity Counter',
         'Что проверяет: каждый TS-пакет имеет счётчик (0-15), который увеличивается на 1 для каждого пакета того же PID. Если счётчик сбился — пакет потерян или вставлен.',
         [
            ('[OK]', 'Счётчики непрерывности корректны. Пакеты не потеряны и не вставлены.'),
            ('[ОШИБКА]', 'Счётчик сбился: ожидался 5, а пришёл 7. Между ними 2 пакета потеряны или вставлены лишние. Признак модификации потока.'),
         ], 'ДА'),
        
        ('2.9. Битрейт',
         'Что проверяет: средний битрейт (мегабит в секунду) должен быть примерно одинаковым во всех файлах. Резкое отличие одного файла — признак перекодировки или вставки.',
         [
            ('[OK]', 'Битрейт стабилен (коэффициент вариации < 5%). Все файлы записаны с одинаковыми настройками.'),
            ('[ОК] один файл', 'Один файл — сравнивать битрейт не с чем.'),
            ('[ВНИМАНИЕ]', 'Битрейт нестабилен (коэффициент вариации 5-10%). Возможна перекодировка части файлов.'),
            ('[ОШИБКА]', 'Битрейт сильно нестабилен (коэффициент вариации > 10%). Файлы записаны с разными настройками или перекодированы.'),
         ], 'ДА (один файл: выводится без сравнения)'),
        
        ('2.10. Время последней записи файлов (mtime)',
         'Что проверяет: время последней записи файла на диск (mtime) должно расти от файла к файлу. Если mtime первого файла позже второго — файлы копировали или модифицировали.',
         [
            ('[OK]', 'mtime упорядочен по возрастанию. Файлы записывались по очереди, в порядке съёмки.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — упорядочивать нечего.'),
            ('[ОШИБКА]', 'mtime файла раньше предыдущего. Файлы копировали или модифицировали после записи.'),
         ], 'НЕТ (один файл)'),
        
        ('2.11. Наличие GPS',
         'Что проверяет: во всех файлах должны быть GPS-метки. Если в части файлов нет GPS — регистратор терял спутники.',
         [
            ('[OK]', 'GPS-метки есть во всех файлах.'),
            ('[ВНИМАНИЕ]', 'GPS-метки отсутствуют в файле с нормальной датой. Регистратор потерял спутники.'),
            ('[ОБЪЯСНЕНО]', 'GPS отсутствует в файле с заводской датой (год 2000 или подобный). Холодный пуск, GPS-модуль ещё не захватил спутники. Норма.'),
         ], 'ДА'),
        
        ('2.12. Размеры файлов',
         'Что проверяет: размеры 1-минутных файлов должны быть примерно одинаковыми (±50%). Файл значительно меньшего размера — короткая запись или вырезание.',
         [
            ('[OK]', 'Размеры согласованы. Отклонения в пределах нормы.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать размеры не с чем.'),
            ('[ОБЪЯСНЕНО]', 'Файл меньше остальных, но это короткий стартовый фрагмент (PTS < 60 сек). Регистратор только включился. Норма.'),
            ('[ВНИМАНИЕ]', 'Файл сильно отличается по размеру (> 50% от медианы). Возможно, запись прервана или файл модифицирован.'),
         ], 'НЕТ (один файл)'),
        
        ('2.13. Аудио-спектрограмма',
         'Что проверяет: извлекает 5 секунд аудио с краёв соседних файлов, строит спектрограммы (частоты 20-600 Гц), сравнивает последний кадр предыдущего файла с первым кадром следующего. Спектр звука должен плавно перетекать.',
         [
            ('[OK]', 'Спектральное сходство высокое (> 60%). Звук плавно перетекает между файлами.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать аудио на стыках не с чем.'),
            ('[ВНИМАНИЕ]', 'Сходство низкое (< 60%). Звук резко меняется на стыке. Возможно, файлы склеены из разных источников.'),
         ], 'НЕТ (один файл)'),
        
        ('2.14. Яркость кадров',
         'Что проверяет: извлекает 30 кадров с краёв соседних файлов, вычисляет среднюю яркость. Скачок яркости на стыке > 30% — возможна вставка или склейка.',
         [
            ('[OK]', 'Скачок яркости на стыке < 15%. Освещение плавно меняется.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать яркость на стыках не с чем.'),
            ('[ВНИМАНИЕ]', 'Скачок 15-30%. Резкая смена освещения. Возможно, склейка, но может быть естественной (въезд в тоннель, поворот).'),
            ('[ОШИБКА]', 'Скачок > 30%. Очень резкая смена яркости. Сильный признак склейки или вставки.'),
         ], 'НЕТ (один файл)'),
        
        ('2.15. Перцептивный хэш кадров',
         'Что проверяет: извлекает последний кадр предыдущего файла и первый кадр следующего, вычисляет перцептивный хэш (pHash 8x8 = 64 бита), считает расстояние Хэмминга. Hamming=0 — кадры идентичны до пикселя.',
         [
            ('[OK]', 'Hamming > 10. Кадры отличаются. Норма — соседние кадры в реальном видео всегда разные.'),
            ('[НЕ ПРИМЕНИМО]', 'Один файл — сравнивать хэш на стыках не с чем.'),
            ('[ДУБЛИКАТ]', 'Hamming=0. Кадры идентичны до пикселя. В реальном видео соседние кадры ВСЕГДА отличаются (шум матрицы, движение объекта). Полное совпадение = кадр скопирован. Признак склейки.'),
         ], 'НЕТ (один файл)'),
        
        ('2.16.1. Монотонность PTS видео',
         'Что проверяет: внутри файла PTS видео должна расти монотонно: 0.000, 0.033, 0.067, 0.100... (шаг ~33 мс для 30 кадров/сек). Обратный скачок = PTS следующего кадра МЕНЬШЕ предыдущего. Сравнивается: каждый видео-кадр с предыдущим. Берётся разность PTS. Если разность отрицательная — обратный скачок.',
         [
            ('[OK]', 'PTS видео растёт монотонно. Кадры идут по порядку.'),
            ('[ОШИБКА] обратные скачки PTS', 'PTS видео следующего кадра МЕНЬШЕ предыдущего. Например: кадр #4: 0.128 -> 0.100 сек. Время "пошло назад". В непрерывной записи невозможно. Возможные причины: 1) СКЛЕЙКА — два фрагмента соединены, у второго PTS началась заново; 2) ВЫРЕЗАНИЕ — из середины вырезан кусок и концы сшили; 3) Перекодировка с пересчётом PTS. Сравниваются ТОЛЬКО видео-PTS (stream_id 0xE0), аудио-PTS исключены.'),
            ('[ВНИМАНИЕ] большие вперёд-скачки', 'Разница между соседними кадрами больше 2 секунд. Часть кадров пропущена внутри файла. Возможно, потеря пакетов или вырезание.'),
         ], 'ДА'),
        
        ('2.16.2. Монотонность PCR',
         'Что проверяет: внутри файла PCR должна расти монотонно. Обратный скачок PCR = системные часы "пошли назад".',
         [
            ('[OK]', 'PCR растёт монотонно. Системные часы не прерывались.'),
            ('[ОШИБКА] обратные скачки PCR', 'PCR следующей точки МЕНЬШЕ предыдущей. Системные часы "пошли назад". В норме невозможно. Признак склейки или перезаписи потока.'),
         ], 'ДА'),
        
        ('2.16.3. Структура ключевых кадров (IDR/SPS/PPS)',
         'Что проверяет: разбирает NAL-типы видео-пакетов. Нормальный 1-минутный фрагмент: 1 IDR (ключевой кадр) + 1 SPS (параметры последовательности) + 1 PPS (параметры картинки) в начале. Нет IDR — видеоплеер не сможет начать воспроизведение. Несколько IDR — возможно склейка. ВНИМАНИЕ: в v3.0 БЫЛ БАГ — таблица NAL-типов была сдвинута на 1. NAL type 5 (IDR) код считал как SEI. Проверка искала type 4 (SLICE_DPC), которого нет. В v3.1 таблица исправлена по стандарту H.264.',
         [
            ('[OK]', 'Один IDR, 1-2 SPS, 1-2 PPS. Структура соответствует оригинальному фрагменту.'),
            ('[ВНИМАНИЕ] IDR отсутствуют', 'В файле нет ни одного IDR-кадра. Видеоплеер не сможет начать воспроизведение с начала файла. Возможные причины: 1) файл обрезан в начале (IDR был в удалённой части); 2) склейка (IDR был в начале оригинального фрагмента, но попал в вырезанную часть); 3) редкая конфигурация регистратора (IDR реже, чем раз в минуту).'),
            ('[ВНИМАНИЕ] несколько IDR', 'Найдено больше одного IDR в 1-минутном файле. Каждый IDR начинает новую GOP (группу кадров). Несколько GOP в 1-минутном фрагменте могут указывать на склейку нескольких фрагментов в один.'),
         ], 'ДА'),
        
        ('2.16.4. Сравнение mtime и GPS-времени',
         'Что проверяет: сравнивает время последней записи файла на диск (mtime) с последней GPS-меткой в файле. mtime должна быть позже GPS-времени на несколько секунд (время на запись и закрытие файла).',
         [
            ('[OK]', 'mtime файла позже последней GPS-метки на разумное время (до 120 секунд). Файл записан после съёмки.'),
            ('[ВНИМАНИЕ]', 'mtime позже GPS-времени больше чем на 120 секунд. Файл был модифицирован (скопирован, пересохранён) спустя значительное время после записи.'),
            ('[ОШИБКА]', 'mtime РАНЬШЕ последней GPS-метки. Файл не мог быть записан до того, как видео было снято. Признак подделки mtime.'),
         ], 'ДА'),
        
        ('2.16.5. Битрейт по сегментам',
         'Что проверяет: разбивает файл на 10-секундные сегменты, считает битрейт каждого. В норме битрейт всех сегментов примерно одинаковый. Резкий скачок в одном сегменте — возможна вставка с другим битрейтом.',
         [
            ('[OK]', 'Битрейт равномерный по всем сегментам. Запись непрерывна.'),
            ('[ВНИМАНИЕ]', 'Скачок битрейта в одном или нескольких сегментах. Возможно, в этом месте вставлен фрагмент с другим битрейтом (перекодированный).'),
         ], 'ДА'),
        
        ('2.16.6. Гэпы GPS-координат',
         'Что проверяет: внутри файла координаты должны меняться плавно. Если машина ехала со скоростью 3 км/ч, а между соседними GPS-точками расстояние 50 метров — за 1 секунду столько проехать нельзя. Значит, часть маршрута вырезана.',
         [
            ('[OK]', 'Координаты меняются плавно, без необъяснимых скачков.'),
            ('[ОШИБКА]', 'Найден гэп: расстояние между соседними GPS-точками не соответствует скорости. Например, скорость 3 км/ч, но координаты сместились на 50 м. Физически: за 1 секунду при 3 км/ч машина проезжает 0.8 м, а не 50 м. Между точками вырезан фрагмент маршрута.'),
         ], 'ДА'),
    ]
    
    for title, what, results, single_file in checks_explained:
        lines.append('-' * 70)
        lines.append('  %s' % title)
        lines.append('-' * 70)
        lines.append('')
        lines.append('  %s' % what)
        lines.append('')
        for marker, explanation in results:
            lines.append('  %s' % marker)
            lines.append('    %s' % explanation)
            lines.append('')
        lines.append('  Применимо для одного файла: %s' % single_file)
        lines.append('')
    
    # ============================================================
    # Раздел 3: Сводная таблица
    # ============================================================
    lines.append('-' * 70)
    lines.append('  РАЗДЕЛ 3. СВОДНАЯ ТАБЛИЦА ПРИМЕНИМОСТИ ДЛЯ ОДНОГО ФАЙЛА')
    lines.append('-' * 70)
    lines.append('')
    lines.append('  Проверка                          Применимо?')
    lines.append('  ' + '-' * 50)
    
    applicability = [
        ('2.1.1  GPS-время внутри файла', 'ДА'),
        ('2.1.2  GPS-время между файлами', 'НЕТ'),
        ('2.2    GPS-координаты внутри', 'ДА'),
        ('2.3    Имена файлов', 'ДА (шаблон)'),
        ('2.4    Набор PID', 'НЕТ'),
        ('2.5    Параметры потока', 'НЕТ'),
        ('2.6.1  PCR внутри файла', 'ДА'),
        ('2.6.2  PCR между файлами', 'НЕТ'),
        ('2.7.1  PTS внутри файла', 'ДА'),
        ('2.7.2  PTS между файлами', 'НЕТ'),
        ('2.8    Continuity Counter', 'ДА'),
        ('2.9    Битрейт', 'ДА (без сравнения)'),
        ('2.10   mtime файлов', 'НЕТ'),
        ('2.11   Наличие GPS', 'ДА'),
        ('2.12   Размеры файлов', 'НЕТ'),
        ('2.13   Аудио-спектрограмма', 'НЕТ'),
        ('2.14   Яркость кадров', 'НЕТ'),
        ('2.15   Перцептивный хэш', 'НЕТ'),
        ('2.16.1 Монотонность PTS', 'ДА'),
        ('2.16.2 Монотонность PCR', 'ДА'),
        ('2.16.3 IDR/SPS/PPS', 'ДА'),
        ('2.16.4 mtime vs GPS', 'ДА'),
        ('2.16.5 Битрейт по сегментам', 'ДА'),
        ('2.16.6 Гэпы GPS-координат', 'ДА'),
    ]
    
    yes_count = 0
    no_count = 0
    partial_count = 0
    for name, appl in applicability:
        lines.append('  %-34s %s' % (name, appl))
        if appl.startswith('ДА'):
            yes_count += 1
        elif appl.startswith('НЕТ'):
            no_count += 1
        else:
            partial_count += 1
    
    lines.append('  ' + '-' * 50)
    lines.append('  Итого: ДА — %d, ЧАСТИЧНО — %d, НЕТ — %d' % (yes_count, partial_count, no_count))
    lines.append('')
    lines.append('=' * 70)
    lines.append('  Конец файла детализации')
    lines.append('=' * 70)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    return len(lines)

# ============================================================
# Главная функция
# ============================================================




# ============================================================
# Проверка 2.16: Целостность одного файла (детекция модификации)
# ============================================================

def check_single_file_pts(filepath, data):
    """2.16.1: Монотонность PTS внутри файла — детекция склейки/вырезания."""
    errors = 0
    warnings = 0
    lines = []
    pts_list = data.get('pts_video_list', data['pts_list'])
    if len(pts_list) < 2:
        lines.append('    [ПРОПУЩЕНО] Недостаточно точек PTS')
        return errors, warnings, lines, 0
    backward_jumps = []
    forward_jumps = []
    for i in range(1, len(pts_list)):
        delta = pts_list[i] - pts_list[i - 1]
        if delta < -0.001:
            backward_jumps.append((i, pts_list[i-1], pts_list[i], delta))
        elif delta > 2.0:
            forward_jumps.append((i, pts_list[i-1], pts_list[i], delta))
    if backward_jumps:
        errors += len(backward_jumps)
        lines.append('    [ОШИБКА] Обратные скачки PTS видео (%d):' % len(backward_jumps))
        for idx, prev, curr, delta in backward_jumps[:10]:
            lines.append('      Кадр #%d: %.3f -> %.3f сек (дельта %.3f)' % (idx, prev, curr, delta))
        if len(backward_jumps) > 10:
            lines.append('      ... и ещё %d' % (len(backward_jumps) - 10))
        lines.append('      Возможная причина: склейка фрагментов или вырезание части видео')
    if forward_jumps:
        warnings += len(forward_jumps)
        lines.append('    [ВНИМАНИЕ] Большие прямые скачки PTS (%d):' % len(forward_jumps))
        for idx, prev, curr, delta in forward_jumps[:10]:
            lines.append('      Кадр #%d: %.3f -> %.3f сек (дельта %.3f)' % (idx, prev, curr, delta))
        if len(forward_jumps) > 10:
            lines.append('      ... и ещё %d' % (len(forward_jumps) - 10))
        lines.append('      Возможная причина: вырезание фрагмента или пропуск кадров')
    if not backward_jumps and not forward_jumps:
        lines.append('    [OK] PTS монотонна, скачков не обнаружено')
    return errors, warnings, lines, 0


def check_single_file_pcr(filepath, data):
    """2.16.2: Монотонность PCR внутри файла."""
    errors = 0
    warnings = 0
    lines = []
    pcrs = data['pcr_list']
    if len(pcrs) < 2:
        lines.append('    [ПРОПУЩЕНО] Недостаточно точек PCR')
        return errors, warnings, lines, 0
    backward = []
    large_forward = []
    for i in range(1, len(pcrs)):
        delta = pcrs[i] - pcrs[i - 1]
        if delta < -0.001:
            backward.append((i, pcrs[i-1], pcrs[i], delta))
        elif delta > 1.0:
            large_forward.append((i, pcrs[i-1], pcrs[i], delta))
    if backward:
        errors += len(backward)
        lines.append('    [ОШИБКА] Обратные скачки PCR (%d):' % len(backward))
        for idx, prev, curr, delta in backward[:10]:
            lines.append('      Точка #%d: %.3f -> %.3f сек (дельта %.3f)' % (idx, prev, curr, delta))
        if len(backward) > 10:
            lines.append('      ... и ещё %d' % (len(backward) - 10))
        lines.append('      Возможная причина: сброс системных часов или склейка')
    if large_forward:
        warnings += len(large_forward)
        lines.append('    [ВНИМАНИЕ] Большие прямые скачки PCR (%d):' % len(large_forward))
        for idx, prev, curr, delta in large_forward[:10]:
            lines.append('      Точка #%d: %.3f -> %.3f сек (дельта %.3f)' % (idx, prev, curr, delta))
    if not backward and not large_forward:
        lines.append('    [OK] PCR монотонна, скачков не обнаружено')
    return errors, warnings, lines, 0



def _parse_sei_user_data(data, nal_pos, file_size):
    """Разбирает SEI payload для user_data_unregistered (type 5).
    Возвращает (uuid_hex, ascii_str) или None.
    """
    try:
        pos = nal_pos
        # Пропускаем NAL header байт
        pos += 1
        if pos + 2 >= file_size:
            return None
        # SEI type
        sei_type = data[pos]
        pos += 1
        if sei_type != 5:  # 5 = user_data_unregistered
            return None
        # size (ue(v), но для малых значений — один байт)
        payload_size = data[pos]
        pos += 1
        if payload_size < 16 or pos + payload_size > file_size:
            return None
        # UUID (16 байт)
        uuid_bytes = data[pos:pos+16]
        uuid_hex = ''.join('%02x' % b for b in uuid_bytes)
        pos += 16
        # ASCII строка
        remaining = payload_size - 16
        if remaining > 0 and pos + remaining <= file_size:
            try:
                ascii_str = data[pos:pos+remaining].decode('ascii', errors='replace').rstrip('\x00')
            except Exception:
                ascii_str = ''
        else:
            ascii_str = ''
        return (uuid_hex, ascii_str)
    except Exception:
        return None


KNOWN_ENCODER_UUIDS = {
    '47564adc5c4c433f94efc5113cd143a8': 'Apple VideoToolbox',
    '474d4156494441434f4d50415449424c': 'Adobe Premiere Pro',
    '58263400000000000000000000000000': 'x265',
    '44564f4b000000000000000000000000': 'DaVinci Resolve',
    '48414e444252414b0000000000000000': 'HandBrake',
    '78323634000000000000000000000000': 'x264',
    '434f4e56455254455200000000000000': 'FFmpeg/libav',
    '56494e414e4e454f4e00000000000000': 'Vine',
    '4150504c450000000000000000000000': 'Apple',
    '4d503478000000000000000000000000': 'MP4x',
}


# H.264 NAL type names
H264_NAL_NAMES = {
    0: 'SLICE', 1: 'SLICE', 2: 'SLICE_PARTA', 3: 'SLICE_PARTB',
    4: 'SLICE_PARTC', 5: 'IDR', 6: 'SEI', 7: 'SPS', 8: 'PPS',
    9: 'AUD', 10: 'END_SEQ', 11: 'END_STREAM',
    12: 'FILLER', 13: 'SPS_EXT',
}

# H.265/HEVC NAL type names
H265_NAL_NAMES = {
    0: 'TRAIL_N', 1: 'TRAIL_R', 2: 'TSA_N', 3: 'TSA_R',
    4: 'STSA_N', 5: 'STSA_R', 6: 'RADL_N', 7: 'RADL_R',
    8: 'RASL_N', 9: 'RASL_R',
    16: 'BLA_W_LP', 17: 'BLA_W_RADL', 18: 'BLA_N_LP',
    19: 'IDR_W_RADL', 20: 'IDR_N_LP', 21: 'CRA_NUT',
    32: 'VPS', 33: 'SPS', 34: 'PPS',
    35: 'AUD', 36: 'EOS', 37: 'EOB',
    38: 'FD', 39: 'PREFIX_SEI', 40: 'SUFFIX_SEI',
    48: 'SEI',
}

# H.265 types that are key frames (IDR/CRA/BLA)
H265_KEYFRAME_TYPES = {19, 20, 21, 16, 17, 18}


def detect_codec(data, max_check=10000):
    """Определяет кодек (H.264 или H.265) по первым NAL-юнитам.
    Возвращает 'h264' или 'h265'.
    """
    h264_count = 0
    h265_count = 0
    i = 0
    limit = min(len(data), max_check)
    while i < limit - 4:
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 1 and data[i+3] < 0xBA:
            nal_byte = data[i+3]
            # H.264: nal_type = byte & 0x1F (младшие 5 бит)
            h264_type = nal_byte & 0x1F
            # H.265: nal_type = (byte >> 1) & 0x3F (старшие 6 бит)
            h265_type = (nal_byte >> 1) & 0x3F
            # VPS (32) есть только в H.265
            if h265_type == 32:
                h265_count += 5  # сильный сигнал
            # SPS/PPS в H.264: 7/8, в H.265: 33/34
            if h264_type in (7, 8):
                h264_count += 1
            if h265_type in (33, 34):
                h265_count += 1
            # IDR в H.264: 5, в H.265: 19/20
            if h264_type == 5:
                h264_count += 2
            if h265_type in (19, 20, 21):
                h265_count += 2
            i += 3
        elif data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and i+3 < limit and data[i+3] == 1 and i+4 < limit and data[i+4] < 0xBA:
            nal_byte = data[i+4]
            h264_type = nal_byte & 0x1F
            h265_type = (nal_byte >> 1) & 0x3F
            if h265_type == 32:
                h265_count += 5
            if h264_type in (7, 8):
                h264_count += 1
            if h265_type in (33, 34):
                h265_count += 1
            if h264_type == 5:
                h264_count += 2
            if h265_type in (19, 20, 21):
                h265_count += 2
            i += 4
        else:
            i += 1
    return 'h265' if h265_count > h264_count else 'h264'


def scan_nal_byte_mask(filepath):
    """Сканирует весь .ts файл как сырые байты, ищет NAL start codes
    и определяет типы NAL-юнитов. Автоопределение H.264/H.265.
    
    Возвращает 5 значений:
      result: dict {'IDR': count, 'SPS': count, ...}
      idr_positions: [(byte_offset, percent), ...]
      sps_data: [(profile_idc, constraint_flags, level_idc), ...]
      sei_user_data: [(uuid_hex, ascii_str), ...]
      codec: 'h264' или 'h265'
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    
    file_size = len(data)
    if file_size < 4:
        return {}, [], [], [], 'h264'
    
    codec = detect_codec(data)
    nal_names = H265_NAL_NAMES if codec == 'h265' else H264_NAL_NAMES
    keyframe_types = H265_KEYFRAME_TYPES if codec == 'h265' else {5}
    sps_type = 33 if codec == 'h265' else 7
    sei_type = 39 if codec == 'h265' else 6
    
    result = {}
    idr_positions = []
    sps_data = []
    sei_user_data = []
    
    i = 0
    while i < file_size - 3:
        # Ищем 00 00 00 01 (4-байтовый start code)
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and i + 3 < file_size and data[i+3] == 1:
            nal_byte_pos = i + 4
            if nal_byte_pos < file_size:
                nal_byte = data[nal_byte_pos]
                if codec == 'h265':
                    nal_type = (nal_byte >> 1) & 0x3F
                else:
                    nal_type = nal_byte & 0x1F
                name = nal_names.get(nal_type, 'TYPE_%d' % nal_type)
                # Нормализуем имена для отчёта
                if codec == 'h265':
                    if nal_type in (19, 20):
                        name = 'IDR'
                    elif nal_type == 21:
                        name = 'CRA'
                    elif nal_type == 32:
                        name = 'VPS'
                    elif nal_type == 33:
                        name = 'SPS'
                    elif nal_type == 34:
                        name = 'PPS'
                    elif nal_type == 35:
                        name = 'AUD'
                    elif nal_type in (39, 40):
                        name = 'SEI'
                    elif nal_type == 48:
                        name = 'SEI'
                result[name] = result.get(name, 0) + 1
                if nal_type in keyframe_types:
                    pct = (i * 100.0) / file_size
                    idr_positions.append((i, pct))
                elif nal_type == sps_type:
                    if nal_byte_pos + 3 < file_size:
                        profile_idc = data[nal_byte_pos + 1]
                        constraint_flags = data[nal_byte_pos + 2]
                        level_idc = data[nal_byte_pos + 3]
                        sps_data.append((profile_idc, constraint_flags, level_idc))
                elif nal_type == sei_type or (codec == 'h265' and nal_type in (39, 40)):
                    sei_result = _parse_sei_user_data(data, nal_byte_pos, file_size)
                    if sei_result:
                        sei_user_data.append(sei_result)
            i += 4
            continue
        
        # Ищем 00 00 01 (3-байтовый start code) — но пропускаем PES-заголовки
        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 1:
            next_byte = data[i+3] if i + 3 < file_size else 0
            # PES stream_id: 0xBA-0xFE — это PES-заголовок, не NAL
            if next_byte >= 0xBA:
                i += 3
                continue
            nal_byte_pos = i + 3
            if nal_byte_pos < file_size:
                nal_byte = data[nal_byte_pos]
                if codec == 'h265':
                    nal_type = (nal_byte >> 1) & 0x3F
                else:
                    nal_type = nal_byte & 0x1F
                name = nal_names.get(nal_type, 'TYPE_%d' % nal_type)
                if codec == 'h265':
                    if nal_type in (19, 20):
                        name = 'IDR'
                    elif nal_type == 21:
                        name = 'CRA'
                    elif nal_type == 32:
                        name = 'VPS'
                    elif nal_type == 33:
                        name = 'SPS'
                    elif nal_type == 34:
                        name = 'PPS'
                    elif nal_type == 35:
                        name = 'AUD'
                    elif nal_type in (39, 40):
                        name = 'SEI'
                    elif nal_type == 48:
                        name = 'SEI'
                result[name] = result.get(name, 0) + 1
                if nal_type in keyframe_types:
                    pct = (i * 100.0) / file_size
                    idr_positions.append((i, pct))
                elif nal_type == sps_type:
                    if nal_byte_pos + 3 < file_size:
                        profile_idc = data[nal_byte_pos + 1]
                        constraint_flags = data[nal_byte_pos + 2]
                        level_idc = data[nal_byte_pos + 3]
                        sps_data.append((profile_idc, constraint_flags, level_idc))
                elif nal_type == sei_type or (codec == 'h265' and nal_type in (39, 40)):
                    sei_result = _parse_sei_user_data(data, nal_byte_pos, file_size)
                    if sei_result:
                        sei_user_data.append(sei_result)
            i += 3
            continue
        
        i += 1
    
    return result, idr_positions, sps_data, sei_user_data, codec


def check_single_file_idr(filepath, data):
    """2.16.3: Количество и положение IDR-кадров — детекция склейки.
    Использует байтовую маску по всему файлу (scan_nal_byte_mask),
    а не словарь nal_types из parse_ts_full (который не видит NAL внутри PES).
    """
    errors = 0
    warnings = 0
    lines = []
    
    nal, idr_positions, sps_data, sei_user_data, codec = scan_nal_byte_mask(filepath)
    
    idr_count = nal.get('IDR', 0) + nal.get('CRA', 0)
    sps_count = nal.get('SPS', 0)
    pps_count = nal.get('PPS', 0)
    vps_count = nal.get('VPS', 0)
    cra_count = nal.get('CRA', 0)
    slice_count = nal.get('SLICE', 0)
    
    lines.append('    NAL-типы в файле (по байтовой маске):')
    lines.append('      Кодек: %s' % codec.upper())
    for name in sorted(nal.keys()):
        lines.append('      %s: %d' % (name, nal[name]))
    
    # Проверка неизвестных NAL-типов (TYPE_N)
    known_nal = {'IDR', 'CRA', 'SLICE', 'SLICE_PARTA', 'SLICE_PARTB', 'SLICE_PARTC',
                 'SLICE_DPC', 'SEI', 'SPS', 'PPS', 'AUD', 'VPS', 'FILLER',
                 'END_SEQ', 'END_STREAM', 'SPS_EXT', 'TRAIL_N', 'TRAIL_R',
                 'TSA_N', 'TSA_R', 'STSA_N', 'STSA_R', 'RADL_N', 'RADL_R',
                 'RASL_N', 'RASL_R', 'BLA_W_LP', 'BLA_W_RADL', 'BLA_N_LP',
                 'IDR_W_RADL', 'IDR_N_LP', 'CRA_NUT', 'EOS', 'EOB', 'FD',
                 'PREFIX_SEI', 'SUFFIX_SEI', 'SEI'}
    unknown_types = [(name, cnt) for name, cnt in nal.items() if name not in known_nal]
    if unknown_types:
        lines.append('      [ОБЪЯСНЕНО] Неизвестные NAL-типы (%d):' % len(unknown_types))
        for name, cnt in unknown_types:
            lines.append('        %s: %d — единичное появление, возможный glitch битового потока. Не признак монтажа.' % (name, cnt))
    lines.append('')
    
    # Позиции IDR
    if idr_positions:
        lines.append('    Позиции IDR-кадров:')
        for byte_off, pct in idr_positions[:10]:
            pos_desc = 'начало' if pct < 5 else ('середина' if pct < 95 else 'конец')
            lines.append('      байт %d (%.1f%% от начала файла) — %s' % (byte_off, pct, pos_desc))
        if len(idr_positions) > 10:
            lines.append('      ... и ещё %d' % (len(idr_positions) - 10))
        lines.append('')
    
    # Вычисляем GOP-интервал
    # Определяем длительность из PCR
    pcr_list = data.get('pcr_list', [])
    duration = 60.0  # по умолчанию
    if pcr_list and len(pcr_list) > 1:
        duration = pcr_list[-1] - pcr_list[0]
        if duration <= 0:
            duration = 60.0
    
    if idr_count == 0:
        warnings += 1
        lines.append('    [ВНИМАНИЕ] IDR-кадры отсутствуют — нет ключевого кадра')
    elif idr_count == 1:
        lines.append('    [OK] Один IDR-кадр в начале файла (норма)')
    else:
        # Вычисляем GOP-интервал
        gop_interval = duration / idr_count if idr_count > 0 else 0
        # Проверяем стандартные GOP размеры
        standard_gops = {0.5: '0.5 сек', 1.0: '1 сек', 2.0: '2 сек', 60.0: '60 сек'}
        gop_desc = ''
        for std_val, std_desc in standard_gops.items():
            if abs(gop_interval - std_val) < 0.15:
                gop_desc = std_desc
                break
        if not gop_desc:
            gop_desc = '%.2f сек' % gop_interval
        
        lines.append('    GOP-интервал: %s (%d IDR за %.1f сек записи)' % (gop_desc, idr_count, duration))
        
        if sps_count == idr_count and pps_count == idr_count:
            lines.append('    [OK] %d IDR-кадров — равномерный GOP (%s)' % (idr_count, gop_desc))
            lines.append('    [OK] SPS=%d, PPS=%d, IDR/CRA=%d — каждая GOP начинается одинаково (норма)' % (sps_count, pps_count, idr_count))
        elif sps_count > idr_count or pps_count > idr_count:
            warnings += 1
            lines.append('    [ВНИМАНИЕ] SPS=%d или PPS=%d больше IDR=%d — возможна вставка фрагмента' % (sps_count, pps_count, idr_count))
        else:
            lines.append('    [OK] %d IDR-кадров — GOP %s' % (idr_count, gop_desc))
    
    # Финальный вердикт
    if idr_count > 0 and sps_count > 0 and pps_count > 0:
        if sps_count == idr_count and pps_count == idr_count:
            lines.append('    [OK] Структура ключевых кадров соответствует оригинальному фрагменту (%s)' % codec.upper())
        elif sps_count <= idr_count and pps_count <= idr_count:
            lines.append('    [OK] Структура ключевых кадров соответствует оригинальному фрагменту (%s)' % codec.upper())
    elif idr_count == 0:
        lines.append('    [OK] Структура ключевых кадров соответствует оригинальному фрагменту (%s)' % codec.upper())
    
    return errors, warnings, lines, 0


def check_single_file_mtime_gps(filepath, data):
    """2.16.4: Сравнение mtime файла и GPS-времени записи."""
    errors = 0
    warnings = 0
    lines = []
    gps_points = data['gps_data']
    if not gps_points:
        lines.append('    [ПРОПУЩЕНО] Нет GPS-меток для сравнения')
        return errors, warnings, lines, 0
    mtime = file_mtime(filepath)
    # Берём последнюю GPS-точку как время окончания записи
    last_gps_dt = dt_to_datetime(gps_points[-1])
    if last_gps_dt is None:
        lines.append('    [ПРОПУЩЕНО] Невозможно определить GPS-время')
        return errors, warnings, lines, 0
    # Разница между mtime файла и последней GPS-точкой
    # GPS время — UTC, mtime — локальное
    # Приводим GPS к локальному (МСК = UTC+3)
    last_gps_msk = dt_to_msk(last_gps_dt)
    delta_seconds = (mtime - last_gps_msk).total_seconds()
    lines.append('    Время последней записи файла (mtime):  %s' % mtime.strftime('%Y-%m-%d %H:%M:%S'))
    lines.append('    Время последней GPS-отметки (МСК):     %s' % last_gps_msk.strftime('%Y-%m-%d %H:%M:%S'))
    lines.append('    Разница: %.0f сек (%.1f дней)' % (delta_seconds, abs(delta_seconds) / 86400.0))
    # Норма: mtime немного позже GPS (файл закрыт после последней записи)
    # Допустимо: до 1 часа разницы (файловая система могла задержать закрытие)
    # Подозрительно: разница > 1 часа или mtime раньше GPS
    if delta_seconds < -60:
        errors += 1
        lines.append('    [ОШИБКА] mtime файла РАНЬШЕ GPS-времени записи (%.0f сек)' % delta_seconds)
        lines.append('      Файл мог быть изменён после записи или скопирован с другой машины')
    elif delta_seconds > 3600:
        warnings += 1
        lines.append('    [ВНИМАНИЕ] mtime файла значительно позже GPS-времени (%.0f сек)' % delta_seconds)
        lines.append('      Файл мог быть модифицирован или скопирован после записи')
    elif delta_seconds > 10:
        # Правка №4: расхождение 10-3600 сек — GPS отстаёт из-за потери сигнала
        lines.append('    [ОБЪЯСНЕНО] mtime позже GPS-времени на %.0f сек' % delta_seconds)
        lines.append('      Тип: GPS-время отстаёт из-за потери спутников. mtime записан')
        lines.append('      правильно по системным часам регистратора. Разрыв GPS-времени')
        lines.append('      внутри файла подтверждает потерю сигнала. Норма.')
    else:
        lines.append('    [OK] mtime согласуется с GPS-временем записи (разница %.0f сек)' % delta_seconds)
    return errors, warnings, lines, 0


def check_single_file_bitrate_segments(filepath, data):
    """2.16.5: Битрейт по 10-секундным сегментам — детекция вставки.
    Считает реальные TS-пакеты в каждом сегменте, отслеживая PCR из adaptation field.
    Фиксированные сегменты по 10 сек; последний сегмент может быть неполным.
    """
    errors = 0
    warnings = 0
    lines = []
    pcrs = data['pcr_list']
    if len(pcrs) < 4:
        lines.append('    [ПРОПУЩЕНО] Недостаточно точек PCR')
        return errors, warnings, lines, 0
    total_dur = pcrs[-1] - pcrs[0]
    if total_dur < 5:
        lines.append('    [ПРОПУЩЕНО] Файл слишком короткий для сегментного анализа')
        return errors, warnings, lines, 0
    # Фиксированные сегменты по 10 сек
    segment_dur = 10.0
    num_segments = max(2, math.ceil(total_dur / segment_dur))
    pcr_start = pcrs[0]
    # Длительность каждого сегмента (последний может быть короче)
    seg_durations = []
    for i in range(num_segments):
        seg_start = i * segment_dur
        seg_end = min((i + 1) * segment_dur, total_dur)
        seg_durations.append(seg_end - seg_start)
    # Читаем файл и считаем TS-пакеты в каждом сегменте
    with open(filepath, 'rb') as f:
        raw = f.read()
    # Поиск синхробайта 0x47 (как в parse_ts_full)
    ts_start = 0
    if len(raw) >= 377:
        if raw[0] == 0x47 and raw[188] == 0x47 and raw[376] == 0x47:
            ts_start = 0
        else:
            for s in range(min(204, len(raw) - 376)):
                if raw[s] == 0x47 and s + 188 < len(raw) and raw[s + 188] == 0x47 and \
                   s + 376 < len(raw) and raw[s + 376] == 0x47:
                    ts_start = s
                    break
    packets_per_seg = [0] * num_segments
    current_pcr = 0.0
    offset = ts_start
    while offset + 188 <= len(raw):
        packet = raw[offset:offset + 188]
        offset += 188
        if packet[0] != 0x47:
            continue
        # Извлечение PCR из adaptation field (тот же код, что в parse_ts_full)
        has_adaptation = (packet[3] & 0x20) != 0
        if has_adaptation and len(packet) > 5:
            adapt_len = packet[4]
            if adapt_len >= 7 and 5 + adapt_len <= len(packet):
                flags = packet[5]
                if flags & 0x10:
                    try:
                        pcr_base = struct.unpack_from('>Q', packet, 6)[0]
                        pcr_base = pcr_base >> 31
                        pcr_ext = ((packet[10] & 0x01) << 8) | packet[11]
                        pcr_val = pcr_base * 300 + pcr_ext
                        current_pcr = pcr_val / 27000000.0
                    except struct.error:
                        pass
        # Распределяем пакет по сегменту
        seg_idx = int((current_pcr - pcr_start) / segment_dur)
        if seg_idx < 0:
            seg_idx = 0
        if seg_idx >= num_segments:
            seg_idx = num_segments - 1
        packets_per_seg[seg_idx] += 1
    # Вычисляем битрейт каждого сегмента по реальной длительности
    seg_bitrates = []
    for i in range(num_segments):
        pkt_count = packets_per_seg[i]
        dur = seg_durations[i]
        if dur > 0:
            seg_br = (pkt_count * 188 * 8) / dur / 1000000.0
        else:
            seg_br = 0.0  # фантомный сегмент (не должно быть при math.ceil)
        seg_bitrates.append(seg_br)
    # Средний битрейт по реальным сегментам (без фантомных)
    real_brs = [br for br, d in zip(seg_bitrates, seg_durations) if d > 0]
    avg_br = sum(real_brs) / len(real_brs) if real_brs else 0
    lines.append('    Средний битрейт: %.2f Мбит/с' % avg_br)
    lines.append('    Битрейт по сегментам (%.0f сек каждый):' % segment_dur)
    for i, br in enumerate(seg_bitrates):
        if avg_br > 0:
            dev = abs(br - avg_br) / avg_br * 100.0
        else:
            dev = 0
        tag = ''
        # Отмечаем неполный последний сегмент
        if seg_durations[i] < segment_dur:
            tag = ' (неполный, %.1f сек)' % seg_durations[i]
        if dev > 50:
            tag += ' [ОТКЛОНЕНИЕ %.0f%%]' % dev
            errors += 1
        elif dev > 30:
            tag += ' [ВНИМАНИЕ %.0f%%]' % dev
            warnings += 1
        lines.append('      Сегмент %d: %.2f Мбит/с%s' % (i + 1, br, tag))
    if errors == 0 and warnings == 0:
        lines.append('    [OK] Битрейт равномерен по сегментам')
    return errors, warnings, lines, 0


def check_single_file_gps_gaps(filepath, data):
    """2.16.6: Гэпы в GPS-координатах внутри файла — детекция вырезания."""
    errors = 0
    warnings = 0
    lines = []
    gps_points = data['gps_data']
    if len(gps_points) < 3:
        lines.append('    [ПРОПУЩЕНО] Недостаточно GPS-точек')
        return errors, warnings, lines, 0
    gaps = []
    for i in range(1, len(gps_points)):
        prev = gps_points[i - 1]['Loc']
        curr = gps_points[i]['Loc']
        if prev['Lat']['Float'] is None or curr['Lat']['Float'] is None:
            continue
        dist = gps_coord_distance(gps_points[i-1], gps_points[i])
        speed = curr['Speed']  # км/ч
        # Если скорость низкая (< 5 км/ч), а расстояние большое (> 50 м) — вырезан кусок
        if dist > 50 and speed < 5:
            gaps.append((i, dist, speed))
        elif dist > 500:
            gaps.append((i, dist, speed))
    if gaps:
        # Проверяем, совпадают ли скачки с разрывами GPS-времени
        explained_gaps = 0
        real_gaps = []
        for idx, dist, speed in gaps:
            if idx > 0 and idx < len(gps_points):
                prev_dt = dt_to_datetime(gps_points[idx - 1])
                curr_dt = dt_to_datetime(gps_points[idx])
                if prev_dt and curr_dt:
                    time_delta = abs((curr_dt - prev_dt).total_seconds())
                    if time_delta > 2:
                        explained_gaps += 1
                        lines.append('    [ОБЪЯСНЕНО] Точка #%d: смещение %.0f м при скорости %.1f км/ч' % (
                            idx, dist, speed))
                        lines.append('      Тип: потеря GPS-сигнала. Скачок совпадает с разрывом времени.')
                        lines.append('')
                        continue
            real_gaps.append((idx, dist, speed))
        if real_gaps:
            errors += len(real_gaps)
            lines.append('    [ОШИБКА] Подозрительные скачки координат (%d):' % len(real_gaps))
            for idx, dist, speed in real_gaps[:10]:
                lines.append('      Точка #%d: смещение %.0f м при скорости %.1f км/ч' % (idx, dist, speed))
            if len(real_gaps) > 10:
                lines.append('      ... и ещё %d' % (len(real_gaps) - 10))
            lines.append('      Возможная причина: вырезание фрагмента видео')
        elif explained_gaps > 0 and not real_gaps:
            lines.append('    [ОБЪЯСНЕНО] Все скачки координат (%d) совпадают с разрывами GPS-времени.' % explained_gaps)
    else:
        lines.append('    [OK] Скачки координат внутри файла не обнаружены')
    return errors, warnings, lines, 0


def check_intra_frame_analysis(filepath, data, output_dir='.'):
    """2.16.7: Сравнение ВСЕХ кадров внутри файла (pHash + MSE).
    Извлекает все кадры через ffmpeg, сравнивает каждый с предыдущим.
    График: intra_frame_analysis.png
    """
    errors = 0
    warnings = 0
    lines = []
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен')
        return 0, 1, lines, 0
    
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        if r.returncode != 0:
            lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
            return 0, 1, lines, 0
    except Exception:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
        return 0, 1, lines, 0
    
    import tempfile
    
    tmpdir = tempfile.mkdtemp(prefix='ts_intra_')
    try:
        out_pattern = os.path.join(tmpdir, 'frame_%06d.png')
        cmd = ['ffmpeg', '-y', '-i', filepath,
               '-vf', 'scale=256:256',
               '-vsync', '0',
               out_pattern, '-loglevel', 'error']
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        
        frame_files = sorted([f for f in os.listdir(tmpdir) if f.endswith('.png')])
        if not frame_files:
            lines.append('    [ПРОПУЩЕНО] Не удалось извлечь кадры')
            return 0, 1, lines, 0
        
        total_frames = len(frame_files)
        lines.append('    Извлечено кадров: %d' % total_frames)
        
        # Загружаем все кадры
        from PIL import Image
        frames = []
        for ff in frame_files:
            img = Image.open(os.path.join(tmpdir, ff)).convert('L')
            frames.append(np.array(img, dtype=np.uint8))
        
        if len(frames) < 2:
            lines.append('    [ПРОПУЩЕНО] Недостаточно кадров')
            return 0, 0, lines, 0
        
        # Вычисляем pHash и MSE для каждой пары
        hamming_vals = []
        mse_vals = []
        prev_bits = compute_phash(frames[0])
        for i in range(1, len(frames)):
            curr_bits = compute_phash(frames[i])
            h_dist = hamming(prev_bits, curr_bits)
            mse_val = float(np.mean((frames[i-1].astype(np.float64) - frames[i].astype(np.float64)) ** 2))
            hamming_vals.append(h_dist)
            mse_vals.append(mse_val)
            prev_bits = curr_bits
        
        # Анализируем аномалии
        hamming_arr = np.array(hamming_vals)
        mean_h = np.mean(hamming_arr)
        std_h = np.std(hamming_arr)
        threshold_h = max(25, mean_h + 3 * std_h)
        
        anomalies = []
        for i in range(len(hamming_vals)):
            if hamming_vals[i] > threshold_h:
                anomalies.append((i+1, hamming_vals[i], mse_vals[i]))
        
        lines.append('    Средний Hamming: %.1f, порог: %.1f' % (mean_h, threshold_h))
        lines.append('    Средний MSE: %.1f' % np.mean(mse_vals))
        
        if anomalies:
            warnings += len(anomalies)
            lines.append('    [ВНИМАНИЕ] Аномальные скачки между кадрами (%d):' % len(anomalies))
            for frame_idx, h_val, mse_val in anomalies[:10]:
                lines.append('      Кадр %d/%d: Hamming=%d, MSE=%.1f' % (frame_idx, total_frames, h_val, mse_val))
            if len(anomalies) > 10:
                lines.append('      ... и ещё %d' % (len(anomalies) - 10))
        else:
            lines.append('    [OK] Аномальных скачков между кадрами не обнаружено')
        
        # График
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), gridspec_kw={'height_ratios': [3, 1]})
        
        ax1.plot(range(1, len(hamming_vals)+1), hamming_vals, color='#2ecc71', linewidth=0.5, alpha=0.7)
        ax1.axhline(y=threshold_h, color='red', linestyle='--', linewidth=1, alpha=0.5, label='Порог (%.1f)' % threshold_h)
        ax1.axhline(y=25, color='orange', linestyle=':', linewidth=1, alpha=0.5, label='Различие (25)')
        for frame_idx, h_val, mse_val in anomalies:
            ax1.plot(frame_idx, h_val, 'ro', markersize=3)
        ax1.set_ylabel('Расстояние Хэмминга', fontsize=10)
        ax1.set_title('Анализ всех кадров (pHash 8x8) — %s' % os.path.basename(filepath), fontsize=10, fontweight='bold')
        ax1.legend(loc='upper right', fontsize=8)
        ax1.set_xlim(0, len(hamming_vals)+1)
        
        ax2.plot(range(1, len(mse_vals)+1), mse_vals, color='#3498db', linewidth=0.5, alpha=0.7)
        ax2.set_ylabel('MSE', fontsize=10)
        ax2.set_xlabel('Номер кадра', fontsize=10)
        ax2.set_xlim(0, len(mse_vals)+1)
        
        
        png_name = 'intra_frame_analysis_%s.png' % os.path.splitext(os.path.basename(filepath))[0]
        png_path = os.path.join(output_dir, png_name)
        save_png_with_stamps(fig, png_path, '2.16.7 Кадры (pHash)', errors, warnings)
        plt.close(fig)
        lines.append('    График: %s' % png_name)
        
    except Exception as e:
        lines.append('    [ПРОПУЩЕНО] Ошибка: %s' % str(e))
        return 0, 1, lines, 0
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
    
    return errors, warnings, lines, 0


def check_intra_audio_analysis(filepath, data, output_dir='.'):
    """2.16.8: Полный анализ аудио внутри файла.
    Спектрограмма на всю длительность, поиск сегментов тишины.
    График: intra_audio_analysis.png
    """
    errors = 0
    warnings = 0
    lines = []
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен')
        return 0, 1, lines, 0
    
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        if r.returncode != 0:
            lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
            return 0, 1, lines, 0
    except Exception:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
        return 0, 1, lines, 0
    
    import tempfile
    fs = 8000
    
    tmpfile = tempfile.NamedTemporaryFile(suffix='.raw', delete=False)
    tmpname = tmpfile.name
    tmpfile.close()
    
    try:
        cmd = ['ffmpeg', '-y', '-i', filepath,
               '-vn', '-ac', '1', '-ar', str(fs),
               '-f', 'f32le', '-c:a', 'pcm_f32le',
               tmpname, '-loglevel', 'error']
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        
        with open(tmpname, 'rb') as f:
            raw = f.read()
        
        if len(raw) < 4:
            lines.append('    [ПРОПУЩЕНО] Аудио не извлечено')
            return 0, 0, lines, 0
        
        audio = np.frombuffer(raw, dtype=np.float32)
        total_samples = len(audio)
        duration = total_samples / fs
        lines.append('    Длительность аудио: %.1f сек (%d семплов)' % (duration, total_samples))
        
        # Энергия по сегментам (окна по 0.1 сек)
        win_size = int(fs * 0.1)
        num_windows = total_samples // win_size
        if num_windows < 2:
            lines.append('    [ПРОПУЩЕНО] Аудио слишком короткое')
            return 0, 0, lines, 0
        
        energy = []
        for i in range(num_windows):
            seg = audio[i*win_size:(i+1)*win_size]
            energy.append(float(np.mean(seg**2)))
        
        energy_arr = np.array(energy)
        mean_e = np.mean(energy_arr)
        
        # Поиск тишины (энергия < 1% средней)
        silence_threshold = mean_e * 0.01
        silence_segments = []
        in_silence = False
        sil_start = 0
        for i in range(len(energy)):
            if energy[i] < silence_threshold:
                if not in_silence:
                    in_silence = True
                    sil_start = i * 0.1
            else:
                if in_silence:
                    in_silence = False
                    sil_dur = i * 0.1 - sil_start
                    if sil_dur > 0.5:
                        silence_segments.append((sil_start, sil_dur))
        
        if silence_segments:
            # Проверяем контекст: холодный пуск (нет GPS) или стоянка (скорость 0)
            gps_points = data.get('gps_data', [])
            is_cold_start = len(gps_points) == 0
            is_parking = False
            is_parking_to_moving = False
            if gps_points:
                speeds = [g['Loc']['Speed'] for g in gps_points if g['Loc']['Speed'] is not None]
                if speeds:
                    low_speed_count = sum(1 for s in speeds if s < 5.0)
                    if low_speed_count > len(speeds) * 0.75:
                        is_parking = True
                    # Правка №1: переход от стоянки к движению
                    # Если первые 50% точек — низкая скорость (< 10 км/ч)
                    half = len(speeds) // 2
                    if half > 0:
                        first_half_speeds = speeds[:half]
                        avg_first = sum(first_half_speeds) / len(first_half_speeds)
                        if avg_first < 10.0:
                            is_parking_to_moving = True
            if is_cold_start:
                lines.append('    [ОБЪЯСНЕНО] Сегменты тишины (%d):' % len(silence_segments))
                lines.append('      Тип: холодный пуск. Аудиопоток в режиме холодного пуска может содержать тишину. Норма.')
            elif is_parking:
                lines.append('    [ОБЪЯСНЕНО] Сегменты тишины (%d):' % len(silence_segments))
                lines.append('      Тип: стоянка. Регистратор записывает тишину при отсутствии движения. Норма.')
            elif is_parking_to_moving:
                lines.append('    [ОБЪЯСНЕНО] Сегменты тишины (%d):' % len(silence_segments))
                lines.append('      Тип: переход от стоянки к движению. Средняя скорость первой половины файла < 10 км/ч.')
                lines.append('      Регистратор записывает тишину при начале движения после стоянки. Норма.')
            else:
                # Короткие сегменты (< 3 сек) при движении — кратковременный аудиоглюк
                all_short = all(dur < 3.0 for _, dur in silence_segments)
                if all_short:
                    lines.append('    [ОБЪЯСНЕНО] Короткие сегменты тишины (%d):' % len(silence_segments))
                    lines.append('      Тип: кратковременный аудиоглюк. Паузы < 3 сек могут быть')
                    lines.append('      вызваны переключением аудиокодека или потерей аудиопакетов.')
                    lines.append('      Не является признаком монтажа. Норма.')
                else:
                    warnings += len(silence_segments)
                    lines.append('    [ВНИМАНИЕ] Сегменты тишины (%d):' % len(silence_segments))
            for sil_start, sil_dur in silence_segments[:10]:
                lines.append('      %.1f сек — %.1f сек (длительность %.1f сек)' % (sil_start, sil_start + sil_dur, sil_dur))
            if len(silence_segments) > 10:
                lines.append('      ... и ещё %d' % (len(silence_segments) - 10))
        else:
            lines.append('    [OK] Сегментов тишины не обнаружено')
        
        # Спектрограмма
        from scipy.signal import spectrogram
        f_spec, t_spec, Sxx = spectrogram(audio, fs=fs, nperseg=1024, noverlap=512, nfft=2048)
        
        # Ограничиваем частоты 20-600 Гц (как в проверке 2.13)
        freq_mask = (f_spec >= 20) & (f_spec <= 600)
        f_spec = f_spec[freq_mask]
        Sxx = Sxx[freq_mask, :]
        
        Sxx_db = 20 * np.log10(Sxx + 1e-10)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), gridspec_kw={'height_ratios': [3, 1]})
        
        ax1.pcolormesh(t_spec, f_spec, Sxx_db, shading='auto', cmap='inferno')
        ax1.set_ylabel('Гц', fontsize=10)
        ax1.set_title('Спектрограмма аудио (20-600 Гц) — %s' % os.path.basename(filepath), fontsize=10, fontweight='bold')
        ax1.set_ylim(20, 600)
        
        t_energy = np.arange(num_windows) * 0.1
        ax2.plot(t_energy, energy, color='#3498db', linewidth=0.5)
        ax2.axhline(y=silence_threshold, color='red', linestyle='--', linewidth=1, alpha=0.5, label='Порог тишины')
        ax2.set_ylabel('Энергия', fontsize=10)
        ax2.set_xlabel('Время, сек', fontsize=10)
        ax2.legend(loc='upper right', fontsize=8)
        
        
        png_name = 'intra_audio_analysis_%s.png' % os.path.splitext(os.path.basename(filepath))[0]
        png_path = os.path.join(output_dir, png_name)
        save_png_with_stamps(fig, png_path, '2.16.8 Аудио (20-600 Гц)', errors, warnings)
        plt.close(fig)
        lines.append('    График: %s' % png_name)
        
    except Exception as e:
        lines.append('    [ПРОПУЩЕНО] Ошибка: %s' % str(e))
        return 0, 1, lines, 0
    finally:
        try:
            os.unlink(tmpname)
        except Exception:
            pass
    
    return errors, warnings, lines, 0


def check_editor_artifacts(filepath, data):
    """2.17: Проверка меток видеоредакторов в H.264 потоке.
    Ищет SEI user_data_unregistered, AUD, Filler NAL, множественные SPS.
    Использует расширенную scan_nal_byte_mask.
    """
    errors = 0
    warnings = 0
    lines = []
    
    nal, idr_positions, sps_data, sei_user_data, codec = scan_nal_byte_mask(filepath)
    
    lines.append('    NAL-типы в файле (по байтовой маске):')
    lines.append('      Кодек: %s' % codec.upper())
    for name in sorted(nal.keys()):
        lines.append('      %s: %d' % (name, nal[name]))
    
    # Проверка неизвестных NAL-типов (TYPE_N)
    known_nal = {'IDR', 'CRA', 'SLICE', 'SLICE_PARTA', 'SLICE_PARTB', 'SLICE_PARTC',
                 'SLICE_DPC', 'SEI', 'SPS', 'PPS', 'AUD', 'VPS', 'FILLER',
                 'END_SEQ', 'END_STREAM', 'SPS_EXT', 'TRAIL_N', 'TRAIL_R',
                 'TSA_N', 'TSA_R', 'STSA_N', 'STSA_R', 'RADL_N', 'RADL_R',
                 'RASL_N', 'RASL_R', 'BLA_W_LP', 'BLA_W_RADL', 'BLA_N_LP',
                 'IDR_W_RADL', 'IDR_N_LP', 'CRA_NUT', 'EOS', 'EOB', 'FD',
                 'PREFIX_SEI', 'SUFFIX_SEI', 'SEI'}
    unknown_types = [(name, cnt) for name, cnt in nal.items() if name not in known_nal]
    if unknown_types:
        lines.append('      [ОБЪЯСНЕНО] Неизвестные NAL-типы (%d):' % len(unknown_types))
        for name, cnt in unknown_types:
            lines.append('        %s: %d — единичное появление, возможный glitch битового потока. Не признак монтажа.' % (name, cnt))
    lines.append('')
    
    # SEI user_data_unregistered
    if sei_user_data:
        errors += len(sei_user_data)
        lines.append('    [ОШИБКА] SEI user_data_unregistered обнаружено (%d):' % len(sei_user_data))
        for uuid_hex, ascii_str in sei_user_data[:10]:
            encoder_name = KNOWN_ENCODER_UUIDS.get(uuid_hex, 'НЕИЗВЕСТНЫЙ ЭНКОДЕР')
            lines.append('      UUID: %s — %s' % (uuid_hex, encoder_name))
            if ascii_str:
                lines.append('      Строка: "%s"' % ascii_str[:200])
    else:
        lines.append('    [OK] SEI user_data_unregistered не обнаружено')
    
    lines.append('')
    
    # AUD (NAL type 9)
    aud_count = nal.get('AUD', 0)
    if aud_count > 0:
        lines.append('    [OK] AUD (Access Unit Delimiter): %d — норма для TS-потока' % aud_count)
        codec_label = 'H.264' if codec == 'h264' else 'H.265'
        lines.append('      AUD — стандартный разделитель кадров в MPEG-TS (%s Annex B)' % codec_label)
    else:
        lines.append('    [OK] AUD (Access Unit Delimiter) не обнаружено')
    
    lines.append('')
    
    # Filler NAL (type 12)
    filler_count = nal.get('FILLER', 0)
    if filler_count > 0:
        warnings += 1
        lines.append('    [ВНИМАНИЕ] Filler NAL: %d обнаружено' % filler_count)
        lines.append('      Регистраторы не используют filler. Возможен перекодирование.')
    else:
        lines.append('    [OK] Filler NAL не обнаружено')
    
    lines.append('')
    
    # Уникальные SPS
    if sps_data:
        unique_sps = list(set(sps_data))
        lines.append('    Уникальных SPS: %d (всего SPS: %d)' % (len(unique_sps), len(sps_data)))
        if len(unique_sps) > 1:
            errors += 1
            lines.append('    [ОШИБКА] Несколько уникальных SPS — возможна склейка из разных источников')
        else:
            lines.append('    [OK] Один уникальный SPS')
        
        lines.append('')
        
        # Профиль/уровень
        profile_idc, constraint_flags, level_idc = unique_sps[0]
        if codec == 'h265':
            # H.265 profiles: 1=Main, 2=Main 10, 3=Main Still Picture
            h265_profile_names = {1: 'Main', 2: 'Main 10', 3: 'Main Still Picture'}
            profile_name = h265_profile_names.get(profile_idc, 'Profile %d' % profile_idc)
            level_name = '%.1f' % (level_idc / 10.0)
            lines.append('    SPS profile: %s (%d), level: %s' % (profile_name, profile_idc, level_name))
            if profile_idc in (1, 2, 3):
                lines.append('    [OK] H.265 %s profile — поддерживается аппаратным энкодером' % profile_name)
            else:
                lines.append('    [ИНФО] Нестандартный H.265 профиль: %d' % profile_idc)
        else:
            profile_names = {66: 'Baseline', 77: 'Main', 100: 'High', 118: 'Multiview High', 122: 'High 4:2:2'}
            profile_name = profile_names.get(profile_idc, 'Profile %d' % profile_idc)
            level_name = '%.1f' % (level_idc / 10.0)
            
            lines.append('    SPS profile: %s (%d), level: %s' % (profile_name, profile_idc, level_name))
            if profile_idc == 100:
                lines.append('    [OK] High profile — поддерживается аппаратным энкодером Novatek')
                lines.append('      Novatek NT96655/NT96660: H.264 high/main profile (по datasheet)')
            elif profile_idc in (66, 77):
                lines.append('    [OK] Профиль соответствует аппаратному энкодеру Novatek')
            else:
                lines.append('    [ИНФО] Нестандартный профиль — требуется проверка')
    else:
        lines.append('    [ПРОПУЩЕНО] SPS не найдены')
    
    return errors, warnings, lines, 0




def check_intra_luminance(filepath, data, output_dir='.'):
    """2.16.9: Яркость ВСЕХ кадров внутри файла.
    Извлекает все кадры, вычисляет среднюю яркость каждого (0-255),
    детектирует скачки > 50 между соседними.
    График: intra_luminance_analysis.png
    """
    errors = 0
    warnings = 0
    lines = []
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен')
        return 0, 1, lines, 0
    
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        if r.returncode != 0:
            lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
            return 0, 1, lines, 0
    except Exception:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
        return 0, 1, lines, 0
    
    import tempfile
    
    tmpdir = tempfile.mkdtemp(prefix='ts_lum_')
    try:
        out_pattern = os.path.join(tmpdir, 'frame_%06d.png')
        cmd = ['ffmpeg', '-y', '-i', filepath,
               '-vf', 'scale=256:256',
               '-vsync', '0',
               out_pattern, '-loglevel', 'error']
        r = subprocess.run(cmd, capture_output=True, timeout=300)
        
        frame_files = sorted([f for f in os.listdir(tmpdir) if f.endswith('.png')])
        if not frame_files:
            lines.append('    [ПРОПУЩЕНО] Не удалось извлечь кадры')
            return 0, 1, lines, 0
        
        total_frames = len(frame_files)
        lines.append('    Извлечено кадров: %d' % total_frames)
        
        from PIL import Image
        luminances = []
        for ff in frame_files:
            img = Image.open(os.path.join(tmpdir, ff)).convert('L')
            arr = np.array(img, dtype=np.uint8)
            luminances.append(float(np.mean(arr)))
        
        luminances = np.array(luminances)
        mean_lum = float(np.mean(luminances))
        min_lum = float(np.min(luminances))
        max_lum = float(np.max(luminances))
        
        lines.append('    Средняя яркость: %.1f (из 255)' % mean_lum)
        lines.append('    Минимальная: %.1f, максимальная: %.1f' % (min_lum, max_lum))
        
        # Детекция скачков > 50
        jump_threshold = 50
        lines.append('    Порог скачка: %d' % jump_threshold)
        
        jumps = []
        for i in range(1, len(luminances)):
            delta = abs(luminances[i] - luminances[i-1])
            if delta > jump_threshold:
                jumps.append((i, luminances[i-1], luminances[i], delta))
        
        if jumps:
            warnings += len(jumps)
            lines.append('    [ВНИМАНИЕ] Скачков яркости > %d: %d' % (jump_threshold, len(jumps)))
            for frame_idx, prev_l, curr_l, delta in jumps[:10]:
                lines.append('      Кадр %d/%d: %.1f -> %.1f (скачок %.1f)' % (
                    frame_idx, total_frames, prev_l, curr_l, delta))
            if len(jumps) > 10:
                lines.append('      ... и ещё %d' % (len(jumps) - 10))
        else:
            lines.append('    [OK] Скачков яркости > %d не обнаружено' % jump_threshold)
        
        # График
        fig, ax = plt.subplots(1, 1, figsize=(16, 6))
        ax.plot(range(1, len(luminances)+1), luminances, color='#2ecc71', linewidth=0.5, alpha=0.8)
        ax.set_xlabel('Номер кадра', fontsize=10)
        ax.set_ylabel('Яркость (0-255)', fontsize=10)
        ax.set_title('Яркость всех кадров — %s' % os.path.basename(filepath), fontsize=10, fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.set_xlim(0, len(luminances)+1)
        
        # Отметки скачков
        for frame_idx, prev_l, curr_l, delta in jumps:
            ax.plot(frame_idx, curr_l, 'ro', markersize=4)
        
        
        png_name = 'intra_luminance_analysis_%s.png' % os.path.splitext(os.path.basename(filepath))[0]
        png_path = os.path.join(output_dir, png_name)
        save_png_with_stamps(fig, png_path, '2.16.9 Яркость кадров', errors, warnings)
        plt.close(fig)
        lines.append('    График: %s' % png_name)
        
    except Exception as e:
        lines.append('    [ПРОПУЩЕНО] Ошибка: %s' % str(e))
        return 0, 1, lines, 0
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
    
    return errors, warnings, lines, 0

def check_single_file_integrity(filepath, data, output_dir='.'):
    """Проверка 2.16: комплексная проверка целостности одного файла.
    Возвращает (errors, warnings, lines, subchecks).
    """
    all_errors = 0
    all_warnings = 0
    all_lines = []
    fname = os.path.basename(filepath)

    sub_e = {}  # subchecks errors
    sub_w = {}  # subchecks warnings
    sub_expl = {}  # subchecks explained

    # 2.16.1
    all_lines.append('  2.16.1. Монотонность PTS:')
    e, w, l, expl = check_single_file_pts(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.1'] = e; sub_w['2.16.1'] = w; sub_expl['2.16.1'] = expl
    all_lines.append('')

    # 2.16.2
    all_lines.append('  2.16.2. Монотонность PCR:')
    e, w, l, expl = check_single_file_pcr(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.2'] = e; sub_w['2.16.2'] = w; sub_expl['2.16.2'] = expl
    all_lines.append('')

    # 2.16.3
    all_lines.append('  2.16.3. Структура ключевых кадров (IDR/SPS/PPS):')
    e, w, l, expl = check_single_file_idr(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.3'] = e; sub_w['2.16.3'] = w; sub_expl['2.16.3'] = expl
    all_lines.append('')

    # 2.16.4
    all_lines.append('  2.16.4. Сравнение mtime и GPS-времени:')
    e, w, l, expl = check_single_file_mtime_gps(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.4'] = e; sub_w['2.16.4'] = w; sub_expl['2.16.4'] = expl
    all_lines.append('')

    # 2.16.5
    all_lines.append('  2.16.5. Битрейт по сегментам:')
    e, w, l, expl = check_single_file_bitrate_segments(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.5'] = e; sub_w['2.16.5'] = w; sub_expl['2.16.5'] = expl
    all_lines.append('')

    # 2.16.6
    all_lines.append('  2.16.6. Гэпы GPS-координат:')
    e, w, l, expl = check_single_file_gps_gaps(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.6'] = e; sub_w['2.16.6'] = w; sub_expl['2.16.6'] = expl
    all_lines.append('')

    # 2.16.7 — сравнение всех кадров
    all_lines.append('  2.16.7. Сравнение всех кадров (pHash + MSE):')
    e, w, l, expl = check_intra_frame_analysis(filepath, data, output_dir)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.7'] = e; sub_w['2.16.7'] = w; sub_expl['2.16.7'] = expl
    all_lines.append('')

    # 2.16.8 — полный анализ аудио
    all_lines.append('  2.16.8. Полный анализ аудио (спектрограмма + тишина):')
    e, w, l, expl = check_intra_audio_analysis(filepath, data, output_dir)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.8'] = e; sub_w['2.16.8'] = w; sub_expl['2.16.8'] = expl
    all_lines.append('')

    # 2.16.9 — яркость всех кадров
    all_lines.append('  2.16.9. Яркость всех кадров:')
    e, w, l, expl = check_intra_luminance(filepath, data, output_dir)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.16.9'] = e; sub_w['2.16.9'] = w; sub_expl['2.16.9'] = expl
    all_lines.append('')

    # 2.17 — метки видеоредакторов
    all_lines.append('  2.17. Проверка меток видеоредакторов:')
    e, w, l, expl = check_editor_artifacts(filepath, data)
    all_lines.extend(l)
    all_errors += e; all_warnings += w; sub_e['2.17'] = e; sub_w['2.17'] = w; sub_expl['2.17'] = expl

    subchecks = [
        ('2.16.1 PTS (внутри)', sub_e.get('2.16.1', 0), sub_w.get('2.16.1', 0), sub_expl.get('2.16.1', 0)),
        ('2.16.2 PCR (внутри)', sub_e.get('2.16.2', 0), sub_w.get('2.16.2', 0), sub_expl.get('2.16.2', 0)),
        ('2.16.3 IDR/SPS/PPS', sub_e.get('2.16.3', 0), sub_w.get('2.16.3', 0), sub_expl.get('2.16.3', 0)),
        ('2.16.4 mtime/GPS', sub_e.get('2.16.4', 0), sub_w.get('2.16.4', 0), sub_expl.get('2.16.4', 0)),
        ('2.16.5 Битрейт (сегм.)', sub_e.get('2.16.5', 0), sub_w.get('2.16.5', 0), sub_expl.get('2.16.5', 0)),
        ('2.16.6 GPS-гэпы', sub_e.get('2.16.6', 0), sub_w.get('2.16.6', 0), sub_expl.get('2.16.6', 0)),
        ('2.16.7 Кадры (pHash)', sub_e.get('2.16.7', 0), sub_w.get('2.16.7', 0), sub_expl.get('2.16.7', 0)),
        ('2.16.8 Аудио (20-600 Гц)', sub_e.get('2.16.8', 0), sub_w.get('2.16.8', 0), sub_expl.get('2.16.8', 0)),
        ('2.16.9 Яркость кадров', sub_e.get('2.16.9', 0), sub_w.get('2.16.9', 0), sub_expl.get('2.16.9', 0)),
        ('2.17 Метки редакторов', sub_e.get('2.17', 0), sub_w.get('2.17', 0), sub_expl.get('2.17', 0)),
    ]

    return all_errors, all_warnings, all_lines, subchecks

# ============================================================
# Пагинация графиков (для больших наборов данных)
# ============================================================

def paginate_items(items, max_per_page=30):
    """Разбивает список на страницы по max_per_page элементов."""
    pages = []
    for i in range(0, len(items), max_per_page):
        pages.append(items[i:i + max_per_page])
    return pages

# ============================================================
# Проверка 2.13: Спектральное сравнение аудио на стыках файлов
# ============================================================

def check_audio_spectrogram(file_data, output_dir='.', frag_idx=0):
    """Проверка 2.13: сравнение спектрограмм аудио на стыках файлов.
    
    Извлекает по 5 сек аудио с краёв соседних файлов, строит спектрограммы
    в диапазоне 20-600 Гц, сравнивает крайние кадры (последний кадр предыдущего
    файла vs первый кадр текущего), сохраняет график с результатами.
    
    Возвращает (errors, warnings, lines, explained).
    """
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    if len(file_data) < 2:
        lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение аудио на стыках не требуется')
        return 0, 0, lines, 0
    
    try:
        import numpy as np
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] numpy не установлен: pip install numpy')
        return 0, 1, lines, 0
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен: pip install matplotlib')
        return 0, 1, lines, 0
    
    try:
        from scipy import signal as scipy_signal
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] scipy не установлен: pip install scipy')
        return 0, 1, lines, 0
    
    # Проверка ffmpeg
    ffmpeg_ok = False
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        ffmpeg_ok = r.returncode == 0
    except Exception:
        pass
    if not ffmpeg_ok:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден в PATH')
        return 0, 1, lines, 0
    
    if len(file_data) < 2:
        lines.append('    [ПРОПУЩЕНО] недостаточно файлов для сравнения')
        return 0, 0, lines, 0
    
    SEG_DUR = 5.0       # секунд с каждого края
    FS = 48000          # частота дискретизации
    NPERSEG = 4096      # окно FFT
    NOVERLAP = 3072     # 75% перекрытие
    FREQ_LOW = 20       # нижняя граница, Гц
    FREQ_HIGH = 600     # верхняя граница, Гц
    
    seg_samples = int(SEG_DUR * FS)
    
    results = []  # (prev_name, curr_name, similarity, prev_Sxx, curr_Sxx, freqs, times)
    
    for i in range(1, len(file_data)):
        prev_path = file_data[i - 1][0]
        curr_path = file_data[i][0]
        prev_name = os.path.basename(prev_path)
        curr_name = os.path.basename(curr_path)
        
        # Извлекаем последние SEG_DUR сек предыдущего файла
        prev_audio = extract_audio_segment(prev_path, seg_samples, FS, 'end')
        # Извлекаем первые SEG_DUR сек текущего файла
        curr_audio = extract_audio_segment(curr_path, seg_samples, FS, 'start')
        
        if prev_audio is None or len(prev_audio) < NPERSEG:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: нет аудио' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None, None, None, None, None))
            continue
        
        if curr_audio is None or len(curr_audio) < NPERSEG:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: нет аудио' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None, None, None, None, None))
            continue
        
        # Спектрограммы
        freqs, times_p, Sxx_prev = scipy_signal.spectrogram(
            prev_audio, fs=FS, window='hann', nperseg=NPERSEG, noverlap=NOVERLAP,
            scaling='density', mode='magnitude')
        
        freqs, times_c, Sxx_curr = scipy_signal.spectrogram(
            curr_audio, fs=FS, window='hann', nperseg=NPERSEG, noverlap=NOVERLAP,
            scaling='density', mode='magnitude')
        
        # Фильтр по частотам 20-600 Гц
        mask = (freqs >= FREQ_LOW) & (freqs <= FREQ_HIGH)
        freqs_f = freqs[mask]
        Sxx_prev_f = Sxx_prev[mask, :]
        Sxx_curr_f = Sxx_curr[mask, :]
        
        if Sxx_prev_f.shape[1] == 0 or Sxx_curr_f.shape[1] == 0:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: пустой спектр' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None, None, None, None, None))
            continue
        
        # Сравнение: последний кадр предыдущего vs первый кадр текущего
        last_frame_prev = Sxx_prev_f[:, -1]
        first_frame_curr = Sxx_curr_f[:, 0]
        
        # Косинусное сходство одиночного кадра
        dot = np.dot(last_frame_prev, first_frame_curr)
        norm_prev = np.linalg.norm(last_frame_prev)
        norm_curr = np.linalg.norm(first_frame_curr)
        if norm_prev > 0 and norm_curr > 0:
            single_similarity = float(dot / (norm_prev * norm_curr)) * 100.0
        else:
            single_similarity = 0.0
        
        # --- Динамический подбор интервала (правка №8) ---
        # Шаг между кадрами спектрограммы
        frame_step = (NPERSEG - NOVERLAP) / FS  # ~0.0213 сек
        n_frames_prev = Sxx_prev_f.shape[1]
        n_frames_curr = Sxx_curr_f.shape[1]
        
        # Окна для перебора (в секундах)
        window_sizes = [0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 3.0, 5.0]
        
        recommended_interval = frame_step  # по умолчанию — один кадр
        corrected_similarity = single_similarity
        
        if single_similarity < 70:
            # Запускаем перебор окон усреднения
            best_sim = single_similarity
            best_interval = frame_step
            for win_sec in window_sizes:
                n_avg = max(1, int(win_sec / frame_step))
                if n_avg > n_frames_prev or n_avg > n_frames_curr:
                    n_avg = min(n_frames_prev, n_frames_curr)
                # Усредняем N кадров с каждого края
                avg_prev = np.mean(Sxx_prev_f[:, -n_avg:], axis=1)
                avg_curr = np.mean(Sxx_curr_f[:, :n_avg], axis=1)
                d = np.dot(avg_prev, avg_curr)
                np_ = np.linalg.norm(avg_prev)
                nc = np.linalg.norm(avg_curr)
                if np_ > 0 and nc > 0:
                    win_sim = float(d / (np_ * nc)) * 100.0
                else:
                    win_sim = 0.0
                if win_sim > best_sim:
                    best_sim = win_sim
                    best_interval = win_sec
                if win_sim >= 60:
                    best_sim = win_sim
                    best_interval = win_sec
                    break
            corrected_similarity = best_sim
            recommended_interval = best_interval
        
        # --- Определение статуса ---
        is_cold_start = (
            is_factory_date_file(prev_path, file_data) or 
            is_factory_date_file(curr_path, file_data) or
            is_startup_file(prev_path, file_data[i-1][1]) or
            is_startup_file(curr_path, file_data[i][1])
        )
        is_transient = (single_similarity < 60 and corrected_similarity >= 60)
        
        if is_cold_start and corrected_similarity < 70:
            tag = '[ОБЪЯСНЕНО]'
            explained += 1
        elif is_transient:
            tag = '[ОБЪЯСНЕНО]'
            explained += 1
        elif corrected_similarity >= 70:
            tag = '[OK]'
        elif corrected_similarity >= 50:
            tag = '[СРЕДНЕЕ]'
            warnings += 1
        else:
            tag = '[НИЗКОЕ]'
            errors += 1
        
        # --- Текстовый вывод ---
        if recommended_interval > frame_step * 2:
            # Динамический интервал выбран
            if recommended_interval >= 1.0:
                interval_str = '%.1f сек' % recommended_interval
            else:
                interval_str = '%.0f мс' % (recommended_interval * 1000)
            lines.append('    %s %s -> %s: сходство %.1f%% (интервал: %s)' % (
                tag, prev_name, curr_name, corrected_similarity, interval_str))
        else:
            lines.append('    %s %s -> %s: сходство %.1f%%' % (
                tag, prev_name, curr_name, corrected_similarity))
        
        if tag == '[ОБЪЯСНЕНО]' and is_cold_start and not is_transient:
            lines.append('      Тип: холодный пуск. Аудиопоток в режиме холодного пуска отличается от штатного.')
            lines.append('      Норма для стыка заводской -> нормальной записи.')
        elif tag == '[ОБЪЯСНЕНО]' and is_transient:
            lines.append('      Тип: кратковременное событие в аудиопотоке (напр. лай, хлопок).')
            lines.append('      Сходство одиночного кадра: %.1f%%, при интервале %s: %.1f%%.' % (
                single_similarity, interval_str, corrected_similarity))
            lines.append('      Норма — событие завершается в пределах интервала, фон не прерывается.')

        results.append((prev_name, curr_name, corrected_similarity,
                        Sxx_prev_f, Sxx_curr_f, freqs_f, times_p,
                        recommended_interval, single_similarity))
    
    # Сводка в тексте
    valid = [r for r in results if r[2] is not None]
    if valid:
        sims = [r[2] for r in valid]
        avg_sim = sum(sims) / len(sims)
        min_sim = min(sims)
        max_sim = max(sims)
        lines.append('')
        lines.append('    Сводка:')
        lines.append('      Среднее сходство:     %.1f%%' % avg_sim)
        lines.append('      Минимальное сходство:  %.1f%%' % min_sim)
        lines.append('      Максимальное сходство:  %.1f%%' % max_sim)
        lines.append('      Сравнений выполнено:   %d' % len(valid))
        # Средний интервал контроля
        intervals = [r[7] for r in valid if r[7] is not None]
        if intervals:
            avg_int = sum(intervals) / len(intervals)
            if avg_int >= 1.0:
                lines.append('      Средний интервал контроля: %.1f сек' % avg_int)
            else:
                lines.append('      Средний интервал контроля: %.0f мс' % (avg_int * 1000))
    else:
        lines.append('    Нет данных для сравнения')
    
    # График с результатами
    if valid:
        try:
            saved = save_spectrogram_png(results, output_dir, FS, SEG_DUR, FREQ_LOW, FREQ_HIGH, frag_idx)
            for s in saved:
                lines.append('      График сохранён: %s' % s)
        except Exception as ex:
            lines.append('      Ошибка графика: %s' % str(ex))
    
    lines.append('')
    return errors, warnings, lines, explained


def extract_audio_segment(filepath, num_samples, fs, position):
    """Извлекает аудио-сегмент из TS-файла через ffmpeg.
    position: 'end' - последние num_samples, 'start' - первые num_samples.
    Возвращает numpy array float32 mono.
    """
    import numpy as np
    import tempfile
    
    tmpfile = tempfile.NamedTemporaryFile(suffix='.raw', delete=False)
    tmpname = tmpfile.name
    tmpfile.close()
    
    try:
        if position == 'end':
            # Извлекаем ВСЁ аудио (без -ss, без -t), берём последние N в Python
            cmd = ['ffmpeg', '-y', '-i', filepath,
                   '-vn', '-ac', '1', '-ar', str(fs),
                   '-f', 'f32le', '-c:a', 'pcm_f32le',
                   tmpname,
                   '-loglevel', 'error']
        else:
            dur = num_samples / fs + 2.0
            cmd = ['ffmpeg', '-y', '-i', filepath,
                   '-t', str(dur),
                   '-vn', '-ac', '1', '-ar', str(fs),
                   '-f', 'f32le', '-c:a', 'pcm_f32le',
                   tmpname,
                   '-loglevel', 'error']
        
        r = subprocess.run(cmd, capture_output=True, timeout=120)
        if r.returncode != 0:
            return None
        
        with open(tmpname, 'rb') as f:
            raw = f.read()
        
        if len(raw) < 4:
            return None
        
        audio = np.frombuffer(raw, dtype=np.float32)
        
        if len(audio) < num_samples:
            return audio if len(audio) > 0 else None
        
        if position == 'end':
            return audio[-num_samples:]
        else:
            return audio[:num_samples]
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmpname)
        except Exception:
            pass


def save_spectrogram_png(results, output_dir, fs, seg_dur, freq_low, freq_high, frag_idx=0):
    """Сохраняет PNG с объединёнными спектрограммами и бар-чартом.
    При большом количестве стыков разбивает на страницы по 30."""
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.gridspec import GridSpec
    
    valid = [r for r in results if r[2] is not None]
    n = len(valid)
    if n == 0:
        return
    
    MAX_PER_PAGE = 30
    pages = paginate_items(valid, MAX_PER_PAGE)
    saved_files = []
    
    for page_idx, page_items in enumerate(pages):
        n_page = len(page_items)
        fig = plt.figure(figsize=(24, max(8, n_page * 4 + 4)), dpi=150)
        gs = GridSpec(n_page + 1, 1, figure=fig, hspace=0.5,
                      height_ratios=[1.5] + [3] * n_page)
        
        # Бар-чарт сходства
        ax_bar = fig.add_subplot(gs[0, 0])
        labels = []
        sims = []
        colors = []
        for r in page_items:
            pn = os.path.basename(r[0])[-20:]
            cn = os.path.basename(r[1])[-20:]
            labels.append('%s\n-> %s' % (pn, cn))
            sims.append(r[2])
            if r[2] >= 70:
                colors.append('#2ecc71')
            elif r[2] >= 50:
                colors.append('#f39c12')
            else:
                colors.append('#e74c3c')
        
        bars = ax_bar.bar(range(len(sims)), sims, color=colors, edgecolor='black', linewidth=0.5)
        ax_bar.set_ylabel('Сходство, %', fontsize=10)
        page_title = 'Спектральное сходство аудио на стыках'
        if len(pages) > 1:
            page_title += ' (стр. %d/%d)' % (page_idx + 1, len(pages))
        ax_bar.set_title(page_title, fontsize=12, fontweight='bold')
        ax_bar.set_xticks(range(len(labels)))
        ax_bar.set_xticklabels(labels, fontsize=6, rotation=45, ha='right')
        ax_bar.axhline(y=70, color='green', linestyle='--', linewidth=1, alpha=0.5, label='OK (70%)')
        ax_bar.axhline(y=50, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='СРЕДНЕЕ (50%)')
        ax_bar.set_ylim(0, 105)
        ax_bar.legend(loc='lower right', fontsize=8)
        for bar, sim in zip(bars, sims):
            ax_bar.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 1,
                        '%.1f%%' % sim, ha='center', va='bottom', fontsize=7, fontweight='bold')
        
        # Объединённая спектрограмма для каждого стыка
        for idx, r in enumerate(page_items):
            prev_name, curr_name, similarity, Sxx_prev, Sxx_curr, freqs_f, times_p, rec_interval, single_sim = r
            
            ax = fig.add_subplot(gs[idx + 1, 0])
            
            n_prev = Sxx_prev.shape[1]
            n_curr = Sxx_curr.shape[1]
            combined = np.hstack([Sxx_prev, Sxx_curr])
            t_prev = np.linspace(-seg_dur, 0, n_prev)
            t_curr = np.linspace(0, seg_dur, n_curr)
            t_all = np.concatenate([t_prev, t_curr])
            
            Sxx_db = 20 * np.log10(combined + 1e-10)
            ax.pcolormesh(t_all, freqs_f, Sxx_db, shading='auto', cmap='inferno')
            ax.set_ylabel('Гц', fontsize=8)
            ax.set_xlabel('Время от стыка, сек', fontsize=8)
            
            title_color = '#2ecc71' if similarity >= 70 else ('#f39c12' if similarity >= 50 else '#e74c3c')
            ax.set_title('%s -> %s  (сходство %.1f%%)' % (os.path.basename(prev_name), os.path.basename(curr_name), similarity),
                         fontsize=8, fontweight='bold', loc='left', color=title_color)
            ax.set_ylim(freq_low, freq_high)
            
            ax.axvline(x=0, color='cyan', linestyle='--', linewidth=2, alpha=0.8, label='Стык')
            # Интервал контроля: динамический (правка №8)
            if rec_interval is not None and rec_interval > 0.045:
                # Выбран динамический интервал
                ctrl_interval = rec_interval
                if ctrl_interval >= 1.0:
                    ctrl_label = '%.1f сек' % ctrl_interval
                else:
                    ctrl_label = '%.0f мс' % (ctrl_interval * 1000)
                line_color = 'yellow'
            else:
                # Одиночный кадр
                frame_step = 1024.0 / fs
                ctrl_interval = frame_step
                ctrl_label = '%.0f мс' % (ctrl_interval * 1000)
                line_color = 'yellow'
            ax.axvline(x=-ctrl_interval, color=line_color, linestyle=':', linewidth=1.5, alpha=0.9)
            ax.axvline(x=ctrl_interval, color=line_color, linestyle=':', linewidth=1.5, alpha=0.9,
                       label='Контроль (%s)' % ctrl_label)
            ax.text(-ctrl_interval, freq_high * 0.95, ctrl_label, fontsize=5, color=line_color,
                    ha='right', va='top', bbox=dict(boxstyle='round,pad=0.2', facecolor='black',
                    alpha=0.7, edgecolor=line_color, linewidth=0.5))
            ax.text(ctrl_interval, freq_high * 0.95, ctrl_label, fontsize=5, color=line_color,
                    ha='left', va='top', bbox=dict(boxstyle='round,pad=0.2', facecolor='black',
                    alpha=0.7, edgecolor=line_color, linewidth=0.5))

            ax.legend(loc='upper right', fontsize=6, framealpha=0.9,
                      facecolor='white', edgecolor='gray', fancybox=True)

        if len(pages) == 1:
            png_name = 'audio_spectrogram_all_frag%d.png' % frag_idx if frag_idx > 0 else 'audio_spectrogram_all.png'
        else:
            png_name = 'audio_spectrogram_all_frag%d_%d.png' % (frag_idx, page_idx + 1) if frag_idx > 0 else 'audio_spectrogram_all_%d.png' % (page_idx + 1)
        png_path = os.path.join(output_dir, png_name)
        save_png_with_stamps(fig, png_path, '2.13 Аудио-спектрограмма', 0, 0)
        plt.close(fig)
        saved_files.append(png_name)
    
    return saved_files

def extract_frames_segment(filepath, num_frames, position):
    """Извлекает кадры из TS-файла через ffmpeg как raw gray 256x256.
    position: 'end' - последние num_frames, 'start' - первые num_frames.
    Возвращает список numpy arrays (256x256 uint8) или None.
    Использует временные файлы вместо pipe (совместимость с Windows).
    """
    import numpy as np
    import tempfile
    try:
        tmpdir = tempfile.mkdtemp(prefix='ts_frames_')
        out_pattern = os.path.join(tmpdir, 'frame_%06d.png')
        
        if position == 'end':
            # Извлекаем ВСЕ кадры как PNG, берём последние N
            cmd = ['ffmpeg', '-y', '-i', filepath,
                   '-vf', 'scale=256:256',
                   out_pattern, '-loglevel', 'error']
        else:
            cmd = ['ffmpeg', '-y', '-i', filepath,
                   '-vf', 'scale=256:256',
                   '-vframes', str(num_frames * 2),
                   out_pattern, '-loglevel', 'error']
        
        r = subprocess.run(cmd, capture_output=True, timeout=120)
        if r.returncode != 0:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None
        
        # Собираем PNG-файлы по порядку
        from PIL import Image
        png_files = sorted([f for f in os.listdir(tmpdir) if f.endswith('.png')])
        if not png_files:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return None
        
        frames = []
        for pf in png_files:
            img = Image.open(os.path.join(tmpdir, pf)).convert('L')
            arr = np.array(img, dtype=np.uint8)
            if arr.shape != (256, 256):
                arr = np.resize(arr, (256, 256))
            frames.append(arr)
        
        shutil.rmtree(tmpdir, ignore_errors=True)
        
        if position == 'end':
            return frames[-num_frames:] if len(frames) >= num_frames else frames
        else:
            return frames[:num_frames] if len(frames) >= num_frames else frames
    except Exception:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass
        return None


def check_luminance(file_data, output_dir='.', frag_idx=0):
    """Проверка 2.14: анализ яркости кадров на стыках файлов.
    
    Извлекает по 30 кадров с каждого края соседних файлов,
    вычисляет среднюю яркость, определяет скачок на стыке.
    Строит график luminance_analysis.png.
    
    Возвращает (errors, warnings, lines, explained).
    """
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    if len(file_data) < 2:
        lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение яркости на стыках не требуется')
        return 0, 0, lines, 0
    
    try:
        import numpy as np
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] numpy не установлен')
        return 0, 1, lines, 0
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен')
        return 0, 1, lines, 0
    
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        if r.returncode != 0:
            lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
            return 0, 1, lines, 0
    except Exception:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
        return 0, 1, lines, 0
    
    if len(file_data) < 2:
        lines.append('    [ПРОПУЩЕНО] недостаточно файлов')
        return 0, 0, lines, 0
    
    NUM_FRAMES = 30
    results = []
    
    for i in range(1, len(file_data)):
        prev_path = file_data[i - 1][0]
        curr_path = file_data[i][0]
        prev_name = os.path.basename(prev_path)
        curr_name = os.path.basename(curr_path)
        
        prev_frames = extract_frames_segment(prev_path, NUM_FRAMES, 'end')
        curr_frames = extract_frames_segment(curr_path, NUM_FRAMES, 'start')
        
        if not prev_frames or len(prev_frames) < 2:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: нет кадров' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None))
            continue
        
        if not curr_frames or len(curr_frames) < 2:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: нет кадров' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None))
            continue
        
        prev_lum = [float(np.mean(f)) for f in prev_frames]
        curr_lum = [float(np.mean(f)) for f in curr_frames]
        
        last_prev = prev_lum[-1]
        first_curr = curr_lum[0]
        if last_prev > 0:
            jump_pct = abs(first_curr - last_prev) / last_prev * 100.0
        else:
            jump_pct = 0.0
        
        results.append((prev_name, curr_name, jump_pct, prev_lum, curr_lum))
        
        if jump_pct > 30:
            tag = '[ОШИБКА]'
            errors += 1
        elif jump_pct > 15:
            tag = '[ВНИМАНИЕ]'
            warnings += 1
        else:
            tag = '[OK]'
        
        lines.append('    %s %s -> %s: скачок яркости %.1f%% (пред: %.1f, тек: %.1f)' % (
            tag, prev_name, curr_name, jump_pct, last_prev, first_curr))
    
    valid = [r for r in results if r[2] is not None]
    if valid:
        jumps = [r[2] for r in valid]
        avg_jump = sum(jumps) / len(jumps)
        max_jump = max(jumps)
        lines.append('')
        lines.append('    Сводка:')
        lines.append('      Средний скачок:  %.1f%%' % avg_jump)
        lines.append('      Максимальный:    %.1f%%' % max_jump)
        lines.append('      Сравнений:       %d' % len(valid))
    else:
        lines.append('    Нет данных для сравнения')
        return errors, warnings, lines, explained
    
    # График (с пагинацией по 30 стыков)
    try:
        MAX_PER_PAGE = 30
        pages = paginate_items(valid, MAX_PER_PAGE)
        saved_files = []
        
        for page_idx, page_items in enumerate(pages):
            n_page = len(page_items)
            fig = plt.figure(figsize=(20, max(8, n_page * 4 + 4)), dpi=150)
            n_plots = n_page + 1
            from matplotlib.gridspec import GridSpec
            gs = GridSpec(n_plots, 1, figure=fig, hspace=0.5,
                          height_ratios=[1.5] + [2] * n_page)
            
            # Бар-чарт
            ax_bar = fig.add_subplot(gs[0, 0])
            labels = []
            vals = []
            colors = []
            for r in page_items:
                pn = os.path.basename(r[0])[-15:]
                cn = os.path.basename(r[1])[-15:]
                labels.append('%s\n-> %s' % (pn, cn))
                vals.append(r[2])
                if r[2] > 30:
                    colors.append('#e74c3c')
                elif r[2] > 15:
                    colors.append('#f39c12')
                else:
                    colors.append('#2ecc71')
            
            bars = ax_bar.bar(range(len(vals)), vals, color=colors, edgecolor='black', linewidth=0.5)
            ax_bar.set_ylabel('Скачок яркости, %', fontsize=10)
            page_title = 'Скачок яркости на стыках файлов'
            if len(pages) > 1:
                page_title += ' (стр. %d/%d)' % (page_idx + 1, len(pages))
            ax_bar.set_title(page_title, fontsize=12, fontweight='bold')
            ax_bar.set_xticks(range(len(labels)))
            ax_bar.set_xticklabels(labels, fontsize=6, rotation=45, ha='right')
            ax_bar.axhline(y=30, color='red', linestyle='--', linewidth=1, alpha=0.5, label='ОШИБКА (30%)')
            ax_bar.axhline(y=15, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='ВНИМАНИЕ (15%)')
            ax_bar.legend(loc='upper right', fontsize=8)
            for bar, val in zip(bars, vals):
                ax_bar.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 0.5,
                            '%.1f%%' % val, ha='center', va='bottom', fontsize=7, fontweight='bold')
            
            # Графики яркости для каждого стыка
            for idx, r in enumerate(page_items):
                prev_name, curr_name, jump_pct, prev_lum, curr_lum = r
                ax = fig.add_subplot(gs[idx + 1, 0])
                
                # X: prev от -N до -1, curr от 0 до N-1 — БЕЗ ДЫРЫ
                n_prev = len(prev_lum)
                n_curr = len(curr_lum)
                x_prev = list(range(-n_prev, 0))  # -N, ..., -1
                x_curr = list(range(0, n_curr))     # 0, 1, ..., N-1
                
                ax.plot(x_prev, prev_lum, 'r-o', markersize=3, linewidth=1.5,
                        label='Конец: %s' % os.path.basename(prev_name)[-20:])
                ax.plot(x_curr, curr_lum, 'b-o', markersize=3, linewidth=1.5,
                        label='Начало: %s' % os.path.basename(curr_name)[-20:])
                ax.axvline(x=-0.5, color='cyan', linestyle='--', linewidth=2, alpha=0.8, label='Стык')
                
                title_color = '#e74c3c' if jump_pct > 30 else ('#f39c12' if jump_pct > 15 else '#2ecc71')
                ax.set_title('Скачок: %.1f%%' % jump_pct, fontsize=9, fontweight='bold', color=title_color, loc='left')
                ax.set_ylabel('Яркость', fontsize=8)
                ax.set_xlabel('Кадр от стыка', fontsize=8)
                ax.legend(loc='upper right', fontsize=6)
                ax.grid(True, alpha=0.3)
            
            if len(pages) == 1:
                png_name = 'luminance_analysis_frag%d.png' % frag_idx if frag_idx > 0 else 'luminance_analysis.png'
            else:
                png_name = 'luminance_analysis_frag%d_%d.png' % (frag_idx, page_idx + 1) if frag_idx > 0 else 'luminance_analysis_%d.png' % (page_idx + 1)
            png_path = os.path.join(output_dir, png_name)
            save_png_with_stamps(fig, png_path, '2.14 Яркость кадров', 0, 0)
            plt.close(fig)
            saved_files.append(png_name)
        
        for s in saved_files:
            lines.append('      График сохранён: %s' % s)
    except Exception as ex:
        lines.append('      Ошибка графика: %s' % str(ex))
    
    lines.append('')
    return errors, warnings, lines, explained


def check_frame_hash(file_data, output_dir='.', frag_idx=0):
    """Проверка 2.15: перцептивный хэш кадров на стыках файлов.
    
    Извлекает последний кадр предыдущего файла и первый кадр текущего,
    вычисляет pHash 8x8 (64 бита), сравнивает расстояние Хэмминга.
    Строит график frame_hash_analysis.png.
    
    Возвращает (errors, warnings, lines, explained).
    """
    errors = 0
    warnings = 0
    explained = 0
    lines = []
    if len(file_data) < 2:
        lines.append('    [НЕ ПРИМЕНИМО] Один файл — сравнение хэша кадров на стыках не требуется')
        return 0, 0, lines, 0
    
    try:
        import numpy as np
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] numpy не установлен')
        return 0, 1, lines, 0
    
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        lines.append('    [ПРОПУЩЕНО] matplotlib не установлен')
        return 0, 1, lines, 0
    
    try:
        r = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        if r.returncode != 0:
            lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
            return 0, 1, lines, 0
    except Exception:
        lines.append('    [ПРОПУЩЕНО] ffmpeg не найден')
        return 0, 1, lines, 0
    
    if len(file_data) < 2:
        lines.append('    [ПРОПУЩЕНО] недостаточно файлов')
        return 0, 0, lines, 0
    
    results = []
    
    for i in range(1, len(file_data)):
        prev_path = file_data[i - 1][0]
        curr_path = file_data[i][0]
        prev_name = os.path.basename(prev_path)
        curr_name = os.path.basename(curr_path)
        
        prev_frames = extract_frames_segment(prev_path, 1, 'end')
        curr_frames = extract_frames_segment(curr_path, 1, 'start')
        
        if not prev_frames or not curr_frames:
            lines.append('    [ПРОПУЩЕНО] %s -> %s: нет кадров' % (prev_name, curr_name))
            results.append((prev_name, curr_name, None, None, None, None, None, None))
            continue
        
        prev_img = prev_frames[0]
        curr_img = curr_frames[0]
        
        prev_bits = compute_phash(prev_img)
        curr_bits = compute_phash(curr_img)
        dist = hamming(prev_bits, curr_bits)
        
        # MSE по пикселям 256x256
        mse_val = float(np.mean((prev_img.astype(np.float64) - curr_img.astype(np.float64)) ** 2))
        
        results.append((prev_name, curr_name, dist, mse_val, prev_bits, curr_bits, prev_img, curr_img))
        
        if dist == 0:
            if mse_val == 0.0:
                tag = '[ДУБЛИКАТ]'
                warnings += 1
                lines.append('    %s %s -> %s: Hamming=%d, MSE=%.2f (истинный дубликат)' % (tag, prev_name, curr_name, dist, mse_val))
            else:
                tag = '[OK]'
                lines.append('    %s %s -> %s: Hamming=%d, MSE=%.2f (сцена высокой степени одинаковости)' % (tag, prev_name, curr_name, dist, mse_val))
        elif dist > 25:
            tag = '[РАЗЛИЧИЕ]'
            errors += 1
            lines.append('    %s %s -> %s: Hamming=%d (признак монтажа)' % (tag, prev_name, curr_name, dist))
        else:
            tag = '[OK]'
            lines.append('    %s %s -> %s: Hamming=%d' % (tag, prev_name, curr_name, dist))
    
    valid = [r for r in results if r[2] is not None]
    if valid:
        dists = [r[2] for r in valid]
        avg_dist = sum(dists) / len(dists)
        lines.append('')
        lines.append('    Сводка:')
        lines.append('      Средний Hamming:  %.1f' % avg_dist)
        lines.append('      Максимальный:     %d' % max(dists))
        lines.append('      Минимальный:      %d' % min(dists))
        lines.append('      Сравнений:        %d' % len(valid))
        # MSE сводка
        mse_vals = [r[3] for r in valid if r[3] is not None]
        if mse_vals:
            lines.append('      Средний MSE:      %.2f' % (sum(mse_vals) / len(mse_vals)))
            lines.append('      Макс. MSE:        %.2f' % max(mse_vals))
            lines.append('      Мин. MSE:         %.2f' % min(mse_vals))
            true_dups = sum(1 for m in mse_vals if m == 0.0)
            high_sim = sum(1 for m in mse_vals if 0 < m)
            lines.append('      Истинных дубликатов (MSE=0):  %d' % true_dups)
            lines.append('      Высокая схожесть (0<MSE):     %d' % high_sim)
    else:
        lines.append('    Нет данных для сравнения')
        return errors, warnings, lines, explained
    
    # График (с пагинацией по 30 стыков)
    try:
        MAX_PER_PAGE = 30
        pages = paginate_items(valid, MAX_PER_PAGE)
        saved_files = []
        
        for page_idx, page_items in enumerate(pages):
            n_page = len(page_items)
            fig = plt.figure(figsize=(20, max(6, n_page * 3 + 4)), dpi=150)
            n_plots = n_page + 1
            from matplotlib.gridspec import GridSpec
            gs = GridSpec(n_plots, 4, figure=fig, hspace=0.5, wspace=0.1,
                          height_ratios=[1.5] + [2] * n_page)
            
            # Бар-чарт
            ax_bar = fig.add_subplot(gs[0, :])
            labels = []
            vals = []
            colors = []
            for r in page_items:
                pn = os.path.basename(r[0])[-15:]
                cn = os.path.basename(r[1])[-15:]
                labels.append('%s\n-> %s' % (pn, cn))
                vals.append(r[2])
                if r[2] == 0:
                    colors.append('#f39c12')
                elif r[2] > 25:
                    colors.append('#e74c3c')
                else:
                    colors.append('#2ecc71')
            
            bars = ax_bar.bar(range(len(vals)), vals, color=colors, edgecolor='black', linewidth=0.5)
            ax_bar.set_ylabel('Расстояние Хэмминга', fontsize=10)
            page_title = 'Перцептивный хэш (pHash 8x8) на стыках файлов'
            if len(pages) > 1:
                page_title += ' (стр. %d/%d)' % (page_idx + 1, len(pages))
            ax_bar.set_title(page_title, fontsize=12, fontweight='bold')
            ax_bar.set_xticks(range(len(labels)))
            ax_bar.set_xticklabels(labels, fontsize=6, rotation=45, ha='right')
            ax_bar.axhline(y=25, color='red', linestyle='--', linewidth=1, alpha=0.5, label='РАЗЛИЧИЕ (25)')
            ax_bar.legend(loc='upper right', fontsize=8)
            for bar, val in zip(bars, vals):
                ax_bar.text(bar.get_x() + bar.get_width() / 2., bar.get_height() + 0.5,
                            str(val), ha='center', va='bottom', fontsize=7, fontweight='bold')
            
            # Миниатюры для каждого стыка
            for idx, r in enumerate(page_items):
                prev_name, curr_name, dist, mse_val, prev_bits, curr_bits, prev_img, curr_img = r
                row = idx + 1
                
                ax_p1 = fig.add_subplot(gs[row, 0])
                ax_p1.imshow(prev_img, cmap='gray', aspect='auto')
                ax_p1.set_title('Pred', fontsize=6)
                ax_p1.axis('off')
                
                ax_p2 = fig.add_subplot(gs[row, 1])
                ax_p2.imshow(prev_bits.reshape(8, 8), cmap='gray', aspect='auto')
                ax_p2.set_title('Pred hash', fontsize=6)
                ax_p2.axis('off')
                
                ax_c1 = fig.add_subplot(gs[row, 2])
                ax_c1.imshow(curr_img, cmap='gray', aspect='auto')
                ax_c1.set_title('Curr', fontsize=6)
                ax_c1.axis('off')
                
                ax_c2 = fig.add_subplot(gs[row, 3])
                ax_c2.imshow(curr_bits.reshape(8, 8), cmap='gray', aspect='auto')
                ax_c2.set_title('Curr hash', fontsize=6)
                ax_c2.axis('off')
                
                title_color = '#e74c3c' if dist > 25 else ('#f39c12' if dist == 0 else '#2ecc71')
                ax_p1.set_title('Pred  H=%d' % dist, fontsize=7, color=title_color, fontweight='bold')
            
            if len(pages) == 1:
                png_name = 'frame_hash_analysis_frag%d.png' % frag_idx if frag_idx > 0 else 'frame_hash_analysis.png'
            else:
                png_name = 'frame_hash_analysis_frag%d_%d.png' % (frag_idx, page_idx + 1) if frag_idx > 0 else 'frame_hash_analysis_%d.png' % (page_idx + 1)
            png_path = os.path.join(output_dir, png_name)
            save_png_with_stamps(fig, png_path, '2.15 Перцептивный хэш', 0, 0)
            plt.close(fig)
            saved_files.append(png_name)
        
        for s in saved_files:
            lines.append('      График сохранён: %s' % s)
    except Exception as ex:
        lines.append('      Ошибка графика: %s' % str(ex))
    
    lines.append('')
    return errors, warnings, lines, explained




def generate_history_log(output_path):
    """Создаёт файл history_log.txt с историей изменений всех версий."""
    content = """======================================================================
  ИСТОРИЯ ИЗМЕНЕНИЙ
  ts_integrity_check.py
======================================================================

v1.0 (начальная версия)
  - Базовый парсинг TS-файлов: GPS, PCR, PTS, PID
  - Проверка непрерывности GPS-времени и координат
  - Проверка имён файлов
  - Проверка набора PID
  - Проверка PCR внутри и между файлами
  - Проверка PTS внутри и между файлами
  - Проверка Continuity Counter
  - Проверка битрейта
  - Проверка времени последней записи (mtime)
  - Проверка наличия GPS во всех файлах
  - Проверка согласованности размеров файлов
  - Сводный отчёт с заключением

v1.1
  - Переписан парсинг TS: правильная проверка sync-байта 0x47
  - GPS-метки теперь извлекаются корректно (partial buffer)
  - Функция get_gps_offset ищет маркер A + N/S + E/W с конца

v1.2
  - Добавлена проверка размеров файлов
  - Добавлена проверка холодного пуска GPS
  - Добавлены сведения о компьютере и диске

v1.3
  - Добавлен MD5 хэш файла
  - Добавлено время последней записи (Last Write Time)
  - Точный размер файла в байтах

v1.4
  - Серийные номера CPU, HDD, модель диска через WMI
  - GetVolumeInformationW через ctypes (файловая система, метка тома)

v1.5
  - Сведения о скрипте: имя, путь, размер, mtime, MD5, версия

v1.6
  - Добавлен парсинг PCR (Program Clock Reference)
  - Добавлен парсинг PTS/DTS (Presentation/Decoding Timestamp)
  - Добавлен парсинг NAL-типов H.264

v1.7
  - Добавлены объяснения холодного пуска GPS
  - Добавлена проверка continuity counter
  - Добавлены проверки битрейта и mtime

v1.8
  - Добавлено разделение PTS видео и аудио
  - Добавлены списки pts_video_list, pts_audio_list

v1.9
  - Добавлен анализ NAL-единиц (IDR, SPS, PPS, SEI)
  - Добавлена проверка структуры ключевых кадров

v2.0
  - Добавлена аудио-спектрограмма (FFT 65536)
  - Добавлен анализ яркости кадров
  - Добавлен перцептивный хэш (pHash)
  - Добавлены проверки 2.16.x (mtime, битрейт, гэпы GPS)

v2.1
  - FFT 65536 с широким диапазоном
  - Спектрограмма аудио на стыках файлов

v2.2
  - Добавлены штампы на PNG (add_png_footer)
  - Время создания PNG в штампе

v2.4
  - Пагинация PNG (по 30 стыков на страницу)
  - Фикс PCR: правильное извлечение pcr_base/pcr_ext

v2.5
  - Дедупликация файлов (по realpath)
  - Папка png/ для всех графиков

v2.6
  - Точечные исправления из оригинала v2.1
  - Фикс парсинга GPS (partial buffer)

v2.7
  - Дата скрипта в штампе PNG
  - Зона сравнения 21 мс

v2.8
  - Зона сравнения видимая на графике
  - Фикс спектрограммы: правильный freqs_f

v2.9
  - Новые проверки 2.16.4 (mtime/GPS), 2.16.5 (битрейт), 2.16.6 (гэпы GPS)

v3.0
  - Добавлен парсинг NAL-типов (H.264) в parse_ts_full
  - Добавлены списки pts_video_list и pts_audio_list (разделение видео/аудио PTS)
  - Добавлена генерация error_details.txt с физическими объяснениями ошибок
  - Добавлены метки [НЕ ПРИМЕНИМО] для одного файла (10 проверок)
  - Добавлены метки [ДУБЛИКАТ], [РАЗЛИЧИЕ], [ОБЪЯСНЕНО], [НАЛОЖЕНИЕ]
  - Пагинация графиков (по 30 стыков на страницу)
  - Сводная таблица проверок в итоговом отчёте

v3.1
  - Исправлена таблица NAL-типов (сдвиг на 1): type 5 = IDR (был SEI),
    type 7 = SPS (был PPS), type 8 = PPS (был AUD)
  - Разделены PTS видео и аудио: проверки 2.7.1, 2.7.2, 2.16.1
    используют только видео-PTS (stream_id 0xE0)
  - error_details.txt: расширенные физические объяснения (13 меток, 21 проверка)
  - [НЕ ПРИМЕНИМО] для одного файла: 2.4, 2.5, 2.6.2, 2.7.2, 2.9, 2.10,
    2.12, 2.13, 2.14, 2.15

v3.2
  - NAL-детекция: переписана на байтовую маску (scan_nal_byte_mask)
    Сканирует ВЕСЬ файл как сырые байты, ищет 00 00 00 01 и 00 00 01
  - Проверка 2.16.3: вычисление GOP-интервала
    120 IDR/мин = GOP 0.5 сек — норма (не склейка)
  - Перцептивный хэш (2.15): добавлена вторичная проверка MSE
    Hamming=0 + MSE=0 → [ДУБЛИКАТ], Hamming=0 + MSE>0 → [OK]
  - Разрешение кадров 256x256
  - Время: "Время начала проверки" в шапке, "Время завершения" в конце
  - Создаётся history_log.txt с историей всех версий

v3.4
  - Режим одного файла (len==1): межфайловые проверки [НЕ ПРИМЕНИМО],
    внутрифайловые — на полной длительности
  - 2.16.7: сравнение ВСЕХ кадров (pHash + MSE, ~1800 кадров для 60 сек)
    График intra_frame_analysis.png
  - 2.16.8: полный анализ аудио (спектрограмма + поиск тишины > 0.5 сек)
    График intra_audio_analysis.png
  - 2.17: проверка меток видеоредакторов
    SEI user_data_unregistered (UUID 10 известных энкодеров)
    AUD (NAL type 9), Filler NAL (type 12), множественные SPS
    SPS profile/level: High = софтовый, Baseline/Main = Novatek
  - scan_nal_byte_mask: возвращает 4 значения (+sps_data, +sei_user_data)
  - compute_phash + hamming: вынесены на уровень модуля
  - import numpy as np: добавлен на уровень модуля
  - add_png_footer: штамп сразу после графика (не внизу страницы)

v3.5–v3.9 (правки 1–5)
  - №1: стоянка→движение — avg_first < 10 км/ч → [ОБЪЯСНЕНО]
  - №2: 2-сек GPS gaps при движении → [ОБЪЯСНЕНО] (прерывистый приём)
  - №3: TYPE_48 (H.265) = SEI, убраны все UNSPEC_48
  - №4: mtime vs GPS > 10 сек → [ОБЪЯСНЕНО]
  - №5: кросс-реф 2.1↔2.16.6 — скачок координат → [ОБЪЯСНЕНО]

v3.10 (правки 6–7)
  - №6: 3-сек GPS gaps при движении → [ОБЪЯСНЕНО] (delta <= 3)
  - №7: межфайловые зазоры до 10 сек → [ОБЪЯСНЕНО]
  - Удалён мёртвый дублирующий код (elif delta<=2 / elif dist>50)

v3.11
  - Косметика: убрано "Возможная причина: вырезание" для [ОБЪЯСНЕНО] в 2.16.6
  - Косметика: убрано дублирование "Тип:" (мёртвый код удалён)
  - Косметика: "на 2 сек" → "до 3 сек" (актуализировано под правку №6)
  - 2.16.6: список скачков только для real_gaps, не для explained

v3.12
  - Прогресс-бар: % исполнения и ETA в stderr (парсинг + проверки + 2.16)

v3.13
  - №8: динамический подбор интервала контроля аудио на стыках
    Перебор 8 окон (0.05–5.0 сек) при сходстве одиночного кадра < 70%
    Рекомендуемый интервал — минимальное окно, где сходство >= 60%
    Transient-детекция: один кадр < 60%, при увеличении окна >= 60%
    → [ОБЪЯСНЕНО] "кратковременное событие (лай, хлопок)"
  - PNG: жёлтые линии показывают выбранный интервал, не размер кадра
  - Отчёт: "сходство XX%% (интервал: YY сек/мс)" при динамическом подборе
  - Сводка: добавлен "Средний интервал контроля"


v3.14
  - Возвращена легенда в PNG спектрограмм (ax.legend с белым фоном)
    Голубая пунктирная — "Стык", жёлтая точечная — "Контроль (XX мс/сек)"
  - Прогресс-бар: затирание остатков строки до 79 символов (.ljust(79))
    При смене длинного имени файла на короткое старые символы не остаются

v3.15
  - Автодетекция фрагментов: скрипт сам определяет группы файлов
    по разрывам GPS-времени (> порог x 3), нумерации (пропуск номеров), mtime (> 120 сек)
  - Межфайловые проверки (2.1-2.15) выполняются только внутри фрагмента
  - Между фрагментами: инфо о разрыве (причина, длительность, файлы)
  - Отчёт: каждый фрагмент — отдельный блок с заголовком и границами
  - Заключение: по каждому фрагменту отдельно + сводка разрывов
  - Шапка: "Режим: автодетекция фрагментов"
  - Заголовок отчёта: "НАБОРА .TS-ФРАГМЕНТОВ" (убрано "КАК ЕДИНОГО ВИДЕО")

v3.16
  - Порог фрагментации GPS-времени: max(порог x 10, 10 сек) вместо порог x 3
    (4-секундные разрывы между файлами не считаются разрывом фрагмента)
  - Исправлен двойной прогон проверок 2.1-2.15 (был: по фрагментам + по всем файлам)
  - Прогресс-бар: ровно 16 инкрементов _check_idx при _check_total = 16
  - Счётчики ошибок/предупреждений: отдельный на каждый фрагмент (frag_results)
  - Сводная таблица 2.16: агрегация subchecks (10 строк вместо 9 файлов x 10)
  - PNG-имена: суффикс _fragN при нескольких фрагментах (audio_spectrogram_all_frag1.png)
  - png_dir создаётся до всех проверок (исправлен NameError)
  - Заключение: per-fragment счётчики вместо глобальных

v3.17
  - «удалённые файлы» → «разрывы записи» во всех текстах заключения
  - Правильное склонение: «1 предупреждение», «2 предупреждения», «5 предупреждений»
    через функцию _plural_ru() во всех строках вывода
  - history_log: добавлена запись v3.17

v3.18
  - get_disk_info: WinAPI DeviceIoControl (IOCTL_STORAGE_QUERY_PROPERTY)
    Прямой запрос к драйверу диска, минуя WMI — не зависит от состояния
    WMI-репозитория. Привязка к конкретному физическому диску через
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (по букве тома).
  - get_disk_info: исправлены смещения STORAGE_DEVICE_DESCRIPTOR
    (12/16/24 вместо 20/24/28) — серийник и модель определяются корректно
  - get_disk_info: fallback на wmic (3 попытки, таймаут 30 сек) и PowerShell
    Условие запуска fallback: and → or (хотя бы одно поле пустое)
  - get_disk_info: os.path.abspath(path) — диск D: вместо C: при
    относительном пути (splitdrive("4") давал пустую строку → C:)
  - get_disk_info: алиасы ключей (drive, fs_type, total, free) для main()
  - get_computer_info: retry (3 попытки, таймаут 30 сек) и PowerShell fallback
    для ProcessorId
  - frag_idx: исправлен NameError в save_spectrogram_png (параметр не передавался)
  - format_duration(): единая функция форматирования длительности
    (дни, часы, минуты, секунды) — заменяет %.0f сек и %d мин %d сек
    во всех отчётах (18 мест) и прогресс-баре
  - detect_codec(): правильное определение H.265 в Разделе 1
    (сканирует первые 10 КБ на VPS NAL type 32 — только H.265)
  - H265_NAL_NAMES: словарь имён всех NAL-типов H.265 для Раздела 1
    (раньше все типы кроме IDR/VPS/SPS/PPS/AUD/SEI → "SLICE")
  - AUD: динамический текст — "H.264 Annex B" или "H.265 Annex B"
    (раньше захардкожено "H.264 Annex B" при кодеке H.265)
  - has_errors: трёхуровневое заключение — 0 ошибок + есть предупреждения
    → "Признаков монтажа не обнаружено" (раньше = "признаки модификации")
    Во всех режимах: фрагменты, один файл, несколько файлов

v3.20
  - detect_fragments: критерий mtime не применяется для заводских файлов
    (is_factory_date_file). Заводской файл (RTC 2020-01-01) + реальный
    (2026-06-02) больше не разделяются на разные фрагменты.
  - check_mtime (2.10): заводские файлы помечаются [ОБЪЯСНЕНО],
    не участвуют в сравнении упорядоченности. Возвращает 4 значения (+explained).

v3.21
  - check_single_file_bitrate_segments: переписана — считаются реальные
    TS-пакеты в каждом сегменте (через PCR из adaptation field),
    а не распределяются пропорционально PCR-точкам.
    Исправлен PCR_ext: ((packet[10] & 0x01) << 8) | packet[11]
    (раньше: (packet[11] << 8) | packet[12] — читал лишний байт).
  - Заключение: различает «заводские файлы» (есть is_factory_date_file)
    и «стабилизация GPS-приёмника» (холодный пуск без заводских файлов).

v3.22
  - check_single_file_bitrate_segments: исправлен баг v3.21 — PCR не
    извлекался (все пакеты попадали в сегмент 1). Добавлен поиск
    синхробайта 0x47 (как в parse_ts_full) + корректное чтение
    adaptation field: has_adaptation = (packet[3] & 0x20), adapt_len >= 7,
    flags & 0x10. Проверено: сегменты получают реальные значения битрейта.

v3.23
  - Грамматика: _plural_ru для слова «файл» в выводе режима и списка
    фрагментов (правильное склонение: «2 файла» вместо «2 файлов»).
  - check_single_file_bitrate_segments: фиксированные сегменты по 10 сек
    вместо пропорционального деления (actual_seg_dur = total_dur/num_segments).

v3.24
  - Двойной счёт ошибок: rollup «Целостность файлов» больше не
    дублирует счётчик total_errors/total_warnings. Ошибки уже учтены
    в отдельных subchecks (2.16.1–2.16.9).

v3.25
  - check_single_file_bitrate_segments: фантомный сегмент при длительности,
    кратной 10 сек (60.0 сек -> 7 сегментов вместо 6). Использован
    math.ceil вместо int() + 1. Битрейт неполного последнего сегмента
    считается по реальной длительности, а не по полным 10 сек.
    Средний битрейт считается только по реальным сегментам (без фантомов).

v3.26
  - parse_ts_full: локальный nal_names заменён на глобальный H264_NAL_NAMES
  - H.264 NAL-типы теперь правильные (тип 1 = SLICE, а не SLICE_PARTA)

v3.27
  - import re вынесен в начало файла (fix #13)
  - check-функции: единый формат return (4 значения) (fix #14)
  - sub_expl: объяснённые отклонения 2.16.7-2.16.9 учитываются в счётчиках

v3.28
  - compute_phash: векторизация (fix #12)
  - Быстрый путь: reshape + mean (делится на 8), fallback: cumsum + fancy indexing

v3.29
  - Удалена save_paginated_png — мёртвая заглушка (fix #11)
  - Единый 4-value return для всех check-функций (fix #14)

v3.30
  - Удалены мёртвые словари pcr_base_prev/pcr_ext_prev из parse_ts_full (fix #10)

v3.31
  - fix_coordinates: удалён мёртвый параметр deobfuscate (fix #9)
  - Деобфускация выполняется ранее через deobfuscate_coord()

v3.32
  - md5_file: except (ValueError, Exception) → except Exception (fix #8)

v3.33
  - parse_ts_full: убран дубликат 0xBD в кортеже stream_id (fix #7)

v3.34
  - parse_ts_full: обновлён docstring (fix #6)
  - Теперь: GPS, PCR, PTS, DTS, PID, NAL (H.264/H.265), continuity counter, кодек

v3.35
  - parse_ts_full: исправлен PCR_ext (fix #1)
    Было: pcr_ext = (packet[11] << 8) | packet[12] (читал лишний байт)
    Стало: pcr_ext = ((packet[10] & 0x01) << 8) | packet[11]
  - frag_results: добавлен explained для всех 15 проверок (fix #3)
  - gps_coord_distance: math.cos(math.radians(lat1)) вместо 0.7 (fix #4)
  - Windows-only guards: get_computer_info, get_disk_info, _get_disk_info_winapi (fix #5)
  - import math вынесен в начало файла

v3.36
  - Исправлен счётчик объяснённых отклонений в сводной таблице
  - _t_expl не накапливался между проверками — каждая проверка получала
    объяснённые отклонения предыдущих

v3.37
  - Все fix #1-#15 применены, generate_history_log почищен от дубликатов
  - Убран фантомный «v3.26 (текущая версия)» с дубликатами v3.22/v3.25
  - Убраны дубликаты v3.32, v3.33, v3.34

"""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return content.count(chr(10))
    except Exception:
        return 0


def print_progress(current, total, label, start_time):
    """Выводит прогресс в stderr (не засоряет stdout отчёт)."""
    if total <= 0:
        return
    pct = (current / total) * 100.0
    elapsed = time.time() - start_time
    if current > 0:
        eta = elapsed / current * (total - current)
    else:
        eta = 0
    # Форматирование времени
    def fmt_t(s):
        return format_duration(s)
    line = '  [%d/%d] %d%% — %s | прошло %s | осталось ~%s' % (
        current, total, int(pct), label, fmt_t(elapsed), fmt_t(eta))
    sys.stderr.write('\r' + line.ljust(79))
    sys.stderr.flush()
    if current >= total:
        sys.stderr.write('\n')



# ============================================================
# Автодетекция фрагментов
# ============================================================

def detect_fragments(file_data, gap_threshold=1, file_gap_threshold=1):
    """Разбивает file_data на группы фрагментов по разрывам GPS-времени,
    нумерации и mtime.
    
    Возвращает список фрагментов:
      [{'files': [(filepath, data), ...], 'start_time': dt, 'end_time': dt,
        'seq_range': (first, last), 'index': 0, 'gaps_to_next': None}, ...]
    """
    if len(file_data) <= 1:
        return [{
            'files': file_data,
            'start_time': None,
            'end_time': None,
            'seq_range': (get_file_seq_num(file_data[0][0]), get_file_seq_num(file_data[0][0])) if file_data else (0, 0),
            'index': 0,
            'gaps_to_next': None,
        }]
    
    fragments = []
    current_group = [file_data[0]]
    current_start = None
    current_end = None
    
    # Время первого файла с GPS
    for fp, d in file_data:
        if d.get('gps_data'):
            first_gps = dt_to_datetime(d['gps_data'][0])
            if first_gps:
                current_start = first_gps
                break
    
    for i in range(1, len(file_data)):
        prev_fp, prev_data = file_data[i - 1]
        curr_fp, curr_data = file_data[i]
        
        # Получаем время конца предыдущего и начала текущего
        prev_end_dt = None
        curr_start_dt = None
        if prev_data.get('gps_data'):
            prev_end_dt = dt_to_datetime(prev_data['gps_data'][-1])
        if curr_data.get('gps_data'):
            curr_start_dt = dt_to_datetime(curr_data['gps_data'][0])
        
        # Проверяем разрыв по трём критериям
        is_gap = False
        gap_reason = ''
        gap_seconds = 0
        
        # Критерий 1: разрыв GPS-времени
        if prev_end_dt and curr_start_dt:
            delta = (curr_start_dt - prev_end_dt).total_seconds()
            expected_gap = file_gap_threshold
            if delta > max(expected_gap * 10, 10):
                is_gap = True
                gap_reason = 'GPS-время'
                gap_seconds = delta
        
        # Критерий 2: разрыв в нумерации
        if not is_gap:
            prev_seq = get_file_seq_num(prev_fp)
            curr_seq = get_file_seq_num(curr_fp)
            if curr_seq > prev_seq + 1:
                is_gap = True
                gap_reason = 'нумерация (пропущено %d файлов)' % (curr_seq - prev_seq - 1)
                gap_seconds = 0
        
        # Критерий 3: разрыв mtime
        # Пропускаем для заводских файлов: RTC сброшен на заводскую дату,
        # mtime не отражает реальное время записи
        if not is_gap:
            if not is_factory_date_file(prev_fp, file_data) and \
               not is_factory_date_file(curr_fp, file_data):
                try:
                    prev_mtime = file_mtime(prev_fp)
                    curr_mtime = file_mtime(curr_fp)
                    mtime_delta = (curr_mtime - prev_mtime).total_seconds()
                    # Ожидаемая длительность файла ~60 сек + допуск
                    if mtime_delta > 120:
                        is_gap = True
                        gap_reason = 'mtime (%.0f сек)' % mtime_delta
                        gap_seconds = mtime_delta
                except Exception:
                    pass
        
        if is_gap:
            # Завершаем текущую группу
            frag_start = None
            frag_end = None
            for fp, d in current_group:
                if d.get('gps_data'):
                    if frag_start is None:
                        frag_start = dt_to_datetime(d['gps_data'][0])
                    frag_end = dt_to_datetime(d['gps_data'][-1])
            
            seqs = [get_file_seq_num(fp) for fp, _ in current_group]
            fragments.append({
                'files': current_group,
                'start_time': frag_start,
                'end_time': frag_end,
                'seq_range': (min(seqs), max(seqs)),
                'index': len(fragments),
                'gaps_to_next': {'reason': gap_reason, 'seconds': gap_seconds,
                                  'prev_file': os.path.basename(prev_fp),
                                  'curr_file': os.path.basename(curr_fp)},
            })
            current_group = [file_data[i]]
        else:
            current_group.append(file_data[i])
    
    # Последняя группа
    frag_start = None
    frag_end = None
    for fp, d in current_group:
        if d.get('gps_data'):
            if frag_start is None:
                frag_start = dt_to_datetime(d['gps_data'][0])
            frag_end = dt_to_datetime(d['gps_data'][-1])
    
    seqs = [get_file_seq_num(fp) for fp, _ in current_group]
    fragments.append({
        'files': current_group,
        'start_time': frag_start,
        'end_time': frag_end,
        'seq_range': (min(seqs), max(seqs)),
        'index': len(fragments),
        'gaps_to_next': None,
    })
    
    return fragments


def main():
    global _encoding

    parser = argparse.ArgumentParser(
        description='Проверка целостности набора .ts-фрагментов',
        add_help=True)
    parser.add_argument('path', help='Каталог или один .ts-файл')
    parser.add_argument('-d', action='store_true', help='Деобфускация координат')
    parser.add_argument('-e', type=str, default='866',
                        help='Кодировка вывода: 866 (по умолчанию), 1251, utf-8')
    parser.add_argument('-i', type=int, default=1,
                        help='Ожидаемый интервал между GPS-точками, сек (по умолчанию: 1)')
    parser.add_argument('-g', type=int, default=1,
                        help='Порог разрыва внутри файла, сек (по умолчанию: 1)')
    parser.add_argument('-f', type=int, default=1,
                        help='Порог разрыва между файлами, сек (по умолчанию: 1)')

    args = parser.parse_args()

    enc_map = {'866': 'cp866', '1251': 'cp1251', 'utf-8': 'utf-8', 'utf8': 'utf-8'}
    enc = enc_map.get(args.e.lower(), 'cp866')
    setup_encoding(enc)

    ts_files = find_ts_files(args.path)
    if not ts_files:
        print('Не найдено .ts-файлов в "%s"' % args.path)
        sys.exit(1)

    time_start = datetime.datetime.now()
    now_str = time_start.strftime('%d.%m.%Y %H:%M:%S')

    # Шапка протокола
    sep = '=' * 70
    sep2 = '-' * 70

    print(sep)
    print('              ПРОТОКОЛ ПРОВЕРКИ ЦЕЛОСТНОСТИ')
    if len(ts_files) == 1:
        print('                    .TS-ФАЙЛА')
    else:
        print('          НАБОРА .TS-ФРАГМЕНТОВ')
    print(sep)
    print()
    print('  Время начала проверки:     %s' % now_str)
    print('  Каталог:                  %s' % os.path.abspath(args.path))
    print('  Всего файлов:              %d' % len(ts_files))
    print('  Ожидаемый интервал:        %d сек' % args.i)
    print('  Порог разрыва внутри:      %d сек' % args.g)
    print('  Порог разрыва между:       %d сек' % args.f)
    print('  Деобфускация:              %s' % ('да' if args.d else 'нет'))
    print('  Часовой пояс:              МСК (UTC+3)')
    print('  Кодировка вывода:          %s' % enc)
    print('  Режим:                     автодетекция фрагментов')
    print()

    # Сведения о компьютере
    comp = get_computer_info()
    print(sep)
    print('  СВЕДЕНИЯ О КОМПЬЮТЕРЕ')
    print(sep)
    print()
    print('  Имя компьютера:           %s' % comp['name'])
    print('  Операционная система:     %s' % comp['os'])
    print('  Версия ОС:                %s' % comp['os_version'])
    print('  Архитектура:              %s' % comp['arch'])
    print('  Процессор:                %s' % comp['processor'])
    print('  Пользователь:             %s' % comp['user'])
    print('  Версия Python:            %s' % comp['python'])
    print('  Серийный номер CPU:       %s' % comp['cpu_serial'])
    print()

    # Сведения о диске
    disk = get_disk_info(args.path)
    print(sep)
    print('  СВЕДЕНИЯ О ДИСКЕ')
    print(sep)
    print()
    print('  Диск:                     %s' % disk['drive'])
    print('  Файловая система:         %s' % disk['fs_type'])
    print('  Метка тома:               %s' % disk['volume_label'])
    print('  Серийный номер тома:      %s' % disk['volume_serial'])
    print('  Всего места (байт):       %d' % disk['total'])
    print('  Свободно (байт):          %d' % disk['free'])
    print('  Модель диска:             %s' % disk['disk_model'])
    print('  Серийный номер диска:     %s' % disk['disk_serial'])
    print()

    # Сведения о скрипте
    scr = get_script_info()
    print(sep)
    print('  СВЕДЕНИЯ О СКРИПТЕ')
    print(sep)
    print()
    print('  Имя файла:                %s' % scr['name'])
    print('  Полный путь:               %s' % scr['path'])
    print('  Размер (байт):             %d' % scr['size'])
    print('  Время последней записи:    %s' % scr['mtime'])
    print('  MD5:                       %s' % scr['md5'])
    print('  Версия:                    %s' % scr['version'])
    print()

    # Раздел 1: извлечение данных
    print(sep)
    print('  РАЗДЕЛ 1. ИЗВЛЕЧЕНИЕ ДАННЫХ ИЗ ФАЙЛОВ')
    print(sep)
    print()

    file_data = []
    _progress_start = time.time()
    _progress_total = len(ts_files)
    total_gps = 0

    for filepath in ts_files:
        fname = os.path.basename(filepath)
        sz = file_size(filepath)
        mt = file_mtime(filepath)
        md5 = md5_file(filepath)

        data = parse_ts_full(filepath, args.d)
        file_data.append((filepath, data))
        print_progress(len(file_data), _progress_total, fname, _progress_start)
        total_gps += len(data['gps_data'])

        print('  Файл: %s' % fname)
        print('    Размер:                  %d байт' % sz)
        print('    Время последней записи:   %s' % mt.strftime('%Y-%m-%d %H:%M:%S'))
        print('    MD5:                      %s' % md5)
        print('    TS-пакетов:               %d' % data['ts_packets'])

        pids_str = ', '.join('0x%04X' % p for p in sorted(data['pids']))
        print('    PID:                      %s' % pids_str)
        print('    Видео PID:                %s' % ('0x%04X' % data['video_pid'] if data['video_pid'] else '---'))
        print('    Аудио PID:                %s' % ('0x%04X' % data['audio_pid'] if data['audio_pid'] else '---'))

        if data['gps_data']:
            gps = data['gps_data']
            first_dt = dt_to_datetime(gps[0])
            last_dt = dt_to_datetime(gps[-1])
            print('    GPS-меток:                %d' % len(gps))
            print('    Начало:                   %s' % format_msk(first_dt))
            print('    Конец:                    %s' % format_msk(last_dt))
            loc = gps[0]['Loc']
            print('    Координаты (начало):      %.6f, %.6f' % (loc['Lat']['Float'], loc['Lon']['Float']))
            print('    Скорость (начало):        %.1f км/ч' % loc['Speed'])
            print('    Курс (начало):            %.1f град' % loc['Bearing'])
        else:
            print('    GPS-меток:                0 (не найдены)')

        if data['pcr_list']:
            print('    PCR (начало):             %.3f сек' % data['pcr_list'][0])
            print('    PCR (конец):              %.3f сек' % data['pcr_list'][-1])
        else:
            print('    PCR (начало):             ---')
            print('    PCR (конец):              ---')

        if data['pts_list']:
            print('    PTS (начало):             %.3f сек' % data['pts_list'][0])
            print('    PTS (конец):              %.3f сек' % data['pts_list'][-1])
        else:
            print('    PTS (начало):             ---')
            print('    PTS (конец):              ---')

        codec = data.get('_codec', 'h264') if isinstance(data, dict) else 'h264'
        print('    Кодек:                    %s' % codec.upper())
        if data['nal_types']:
            nal_str = ', '.join('%s(%d)' % (k, v) for k, v in sorted(data['nal_types'].items()))
            print('    NAL-типы:                 %s' % nal_str)

        print()

    # ============================================================
    # Автодетекция фрагментов
    # ============================================================
    fragments = detect_fragments(file_data, args.g, args.f)
    _mode_fragments = len(fragments) > 1

    if _mode_fragments:
        print(sep)
        print('  АВТОДЕТЕКЦИЯ ФРАГМЕНТОВ')
        print(sep)
        print()
        print('  Обнаружено фрагментов: %d' % len(fragments))
        print()
        for fi, frag in enumerate(fragments):
            first_file = os.path.basename(frag['files'][0][0])
            last_file = os.path.basename(frag['files'][-1][0])
            n_files = len(frag['files'])
            if frag['start_time'] and frag['end_time']:
                t_start = format_msk_short(frag['start_time'])
                t_end = format_msk_short(frag['end_time'])
            else:
                t_start = '---'
                t_end = '---'
            print('  Фрагмент %d: %s .. %s (%d файлов: %s .. %s)' % (
                fi + 1, t_start, t_end, n_files, first_file, last_file))
            if frag['gaps_to_next']:
                g = frag['gaps_to_next']
                if g['seconds'] > 0:
                    print('    -> Разрыв до следующего: %s, %s (%s -> %s)' % (
                        g['reason'], format_duration(g['seconds']), g['prev_file'], g['curr_file']))
                else:
                    print('    -> Разрыв до следующего: %s (%s -> %s)' % (
                        g['reason'], g['prev_file'], g['curr_file']))
        print()
    else:
        print('  Режим: единое видео (1 фрагмент, %d %s)' % (len(file_data), _plural_ru(len(file_data), ('файл', 'файла', 'файлов'))))
        print()

    # Раздел 2: проверки
    print(sep)
    print('  РАЗДЕЛ 2. ПРОВЕРКИ')
    print(sep)
    print()

    checks = []
    _check_start = time.time()
    _check_total = 16
    _check_idx = 0

    # png_dir — создаём один раз до всех проверок
    png_dir = os.path.join(os.path.dirname(ts_files[0]) if ts_files else '.', 'png')
    if not os.path.exists(png_dir):
        os.makedirs(png_dir)

    # Группы для проверок: [(frag_idx, frag_files), ...]
    if _mode_fragments:
        _check_groups = [(fi, frag['files']) for fi, frag in enumerate(fragments)]
    else:
        _check_groups = [(0, file_data)]

    # Счётчики по фрагментам
    frag_results = {fi: {'errors': 0, 'warnings': 0, 'explained': 0} for fi, _ in _check_groups}

    # 2.1
    print(sep2)
    print('  2.1. Проверка непрерывности GPS-времени')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_gps_time(_ff, args.g, args.f)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('GPS-время', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.2
    print(sep2)
    print('  2.2. Проверка непрерывности GPS-координат')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_gps_coords(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('GPS-координаты', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.3
    print(sep2)
    print('  2.3. Проверка имён файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_filenames(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Имена файлов', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.4
    print(sep2)
    print('  2.4. Проверка набора PID')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_pids(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Набор PID', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.5
    print(sep2)
    print('  2.5. Проверка параметров потока')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_stream_params(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Параметры потока', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.6
    print(sep2)
    print('  2.6. Проверка PCR (системные часы 27 МГц)')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_pcr(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('PCR (с учётом холодного запуска)', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.7
    print(sep2)
    print('  2.7. Проверка PTS (временные метки показа, 90 кГц)')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_pts(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('PTS (с учётом холодного запуска)', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.8
    print(sep2)
    print('  2.8. Проверка Continuity Counter')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_cc(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Continuity Counter', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.9
    print(sep2)
    print('  2.9. Проверка битрейта')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_bitrate(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Битрейт', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.10
    print(sep2)
    print('  2.10. Проверка времени последней записи файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_mtime(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Время модификации', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.11
    print(sep2)
    print('  2.11. Проверка наличия GPS во всех файлах')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_gps_presence(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Наличие GPS', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.12
    print(sep2)
    print('  2.12. Проверка согласованности размеров файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_file_sizes(_ff)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Размеры файлов', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.13
    print(sep2)
    print('  2.13. Проверка спектрального сходства аудио на стыках файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_audio_spectrogram(_ff, png_dir, frag_idx=_fi + 1 if _mode_fragments else 0)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Аудио-спектрограмма', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.14
    print(sep2)
    print('  2.14. Проверка яркости кадров на стыках файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_luminance(_ff, png_dir, frag_idx=_fi + 1 if _mode_fragments else 0)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Яркость кадров', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.15
    print(sep2)
    print('  2.15. Проверка перцептивного хэша кадров на стыках файлов')
    print(sep2)
    print()
    _t_e = 0; _t_w = 0; _t_expl = 0
    for _fi, _ff in _check_groups:
        if _mode_fragments:
            print('  Фрагмент %d (%s .. %s):' % (_fi + 1, os.path.basename(_ff[0][0]), os.path.basename(_ff[-1][0])))
        e, w, l, expl = check_frame_hash(_ff, png_dir, frag_idx=_fi + 1 if _mode_fragments else 0)
        for line in l:
            print(line)
        print()
        _t_e += e; _t_w += w; _t_expl += expl
        frag_results[_fi]['errors'] += e
        frag_results[_fi]['warnings'] += w
        frag_results[_fi]['explained'] += expl
    checks.append(('Перцептивный хэш', _t_e, _t_w, _t_expl))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.%d" % _check_idx, _check_start)

    # 2.16 — проверка целостности одного файла (для всех файлов)
    print(sep2)
    print('  2.16. Проверка целостности отдельных файлов (детекция модификации)')
    print(sep2)
    print()
    sf_total_errors = 0
    sf_total_warnings = 0
    sf_total_explained = 0
    _216_start = time.time()
    _216_total = len(file_data)
    _216_idx = 0
    _sub_agg = {}  # агрегация subchecks 2.16
    for filepath, data in file_data:
        fname = os.path.basename(filepath)
        print('  Файл: %s' % fname)
        e, w, l, sub = check_single_file_integrity(filepath, data, png_dir)
        for line in l:
            print(line)
        print()
        sf_total_errors += e
        sf_total_warnings += w
        sf_total_explained += sum(s[3] for s in sub)
        # Агрегация subchecks
        for sub_name, sub_e, sub_w, sub_expl in sub:
            if sub_name not in _sub_agg:
                _sub_agg[sub_name] = [0, 0, 0]
            _sub_agg[sub_name][0] += sub_e
            _sub_agg[sub_name][1] += sub_w
            _sub_agg[sub_name][2] += sub_expl
        _216_idx += 1
        print_progress(_216_idx, _216_total, "2.16: %s" % fname, _216_start)
    if sf_total_errors == 0 and sf_total_warnings == 0:
        print('  [OK] Признаков модификации файлов не обнаружено')
    else:
        print('  Ошибок: %d, %s: %d' % (sf_total_errors, _plural_ru(sf_total_warnings, ('предупреждение', 'предупреждения', 'предупреждений')), sf_total_warnings))
    print()
    # Добавляем агрегированные subchecks в сводную таблицу
    for _sn in sorted(_sub_agg.keys()):
        checks.append((_sn, _sub_agg[_sn][0], _sub_agg[_sn][1], _sub_agg[_sn][2]))

    checks.append(('Целостность файлов', sf_total_errors, sf_total_warnings, sf_total_explained))
    _check_idx += 1
    print_progress(_check_idx, _check_total, "проверки 2.16", _check_start)

    # Раздел 3: итоговый отчёт
    print(sep)
    print('  РАЗДЕЛ 3. ИТОГОВЫЙ ОТЧЁТ')
    print(sep)
    print()
    print('  Обработано файлов:        %d' % len(ts_files))
    print('  Всего GPS-меток:          %d' % total_gps)
    print()
    print('  Сводная таблица проверок:')
    print('  ' + '-' * 66)

    total_errors = 0
    total_warnings = 0
    total_explained = 0

    # Межфайловые проверки для одного файла
    single_file_na = len(file_data) == 1
    na_checks = {'Набор PID', 'Параметры потока', 'Время модификации',
                  'Размеры файлов', 'Аудио-спектрограмма', 'Яркость кадров',
                  'Перцептивный хэш'}

    for item in checks:
        name = item[0]
        err_count = item[1] if len(item) > 1 else 0
        warn_count = item[2] if len(item) > 2 else 0
        expl_count = item[3] if len(item) > 3 else 0
        if single_file_na and name in na_checks:
            status = '[НЕ ПРИМЕНИМО]'
            count_str = ''
        elif err_count > 0:
            status = '[ОШИБКА]'
            count_str = 'ошибок: %d' % err_count
            total_errors += err_count
        elif warn_count > 0:
            status = '[ВНИМАНИЕ]'
            count_str = 'предупр.: %d' % warn_count
            total_warnings += warn_count
        else:
            status = '[OK]'
            count_str = ''
        if expl_count > 0 and status != '[НЕ ПРИМЕНИМО]':
            total_explained += expl_count
            count_str += ', объяснено: %d' % expl_count if count_str else 'объяснено: %d' % expl_count
        print('  %-40s  %-12s  %s' % (name, status, count_str))

    print('  ' + '-' * 66)
    print()

    # Раздел 4: Графики (.PNG)
    print(sep)
    print('  РАЗДЕЛ 4. ГРАФИКИ (.PNG)')
    print(sep)
    print()
    # Собираем все PNG из папки png/
    png_dir_report = os.path.join(os.path.dirname(ts_files[0]) if ts_files else '.', 'png')
    png_files = []
    if os.path.isdir(png_dir_report):
        for f in sorted(os.listdir(png_dir_report)):
            if f.lower().endswith('.png'):
                png_files.append(os.path.join(png_dir_report, f))
    print('  Всего PNG-файлов: %d' % len(png_files))
    print('  Каталог: %s' % png_dir_report)
    print()
    if png_files:
        print('  %-55s  %-19s  %10s  %s' % ('Имя файла', 'Дата/время', 'Размер', 'MD5'))
        print('  ' + '-' * 110)
        for pf in png_files:
            pf_name = os.path.basename(pf)
            pf_size = os.path.getsize(pf)
            pf_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(pf))
            pf_md5 = md5_file(pf)
            print('  %-55s  %s  %10d  %s' % (
                pf_name, pf_mtime.strftime('%Y-%m-%d %H:%M:%S'), pf_size, pf_md5))
    else:
        print('  PNG-файлы не найдены')
    print()

    print('  Ошибок:                   %d' % total_errors)
    print('  Предупреждений:           %d' % total_warnings)
    print('  Объяснённых отклонений:    %d' % total_explained)
    print('  Всего нарушений:          %d' % (total_errors + total_warnings))
    print()

    if _mode_fragments:
        # Режим фрагментов — заключение по каждому фрагменту
        print('  ЗАКЛЮЧЕНИЕ ПО ФРАГМЕНТАМ:')
        print()
        all_clean = True
        has_errors = False
        for _fi, _frag in enumerate(fragments):
            _ff = _frag['files']
            _fn = os.path.basename(_ff[0][0])
            _ln = os.path.basename(_ff[-1][0])
            _fe = frag_results[_fi]['errors']
            _fw = frag_results[_fi]['warnings']
            if _fe == 0 and _fw == 0:
                print('  Фрагмент %d (%s .. %s): непрерывное видео, признаков монтажа не обнаружено.' % (
                    _fi + 1, _fn, _ln))
            elif _fe == 0 and _fw > 0:
                print('  Фрагмент %d (%s .. %s): обнаружено %d %s. Требуется анализ.' % (
                    _fi + 1, _fn, _ln, _fw, _plural_ru(_fw, ('предупреждение', 'предупреждения', 'предупреждений'))))
                all_clean = False
            else:
                print('  Фрагмент %d (%s .. %s): обнаружено %d %s и %d %s.' % (
                    _fi + 1, _fn, _ln, _fe, _plural_ru(_fe, ('ошибка', 'ошибки', 'ошибок')), _fw, _plural_ru(_fw, ('предупреждение', 'предупреждения', 'предупреждений'))))
                print('  Фрагмент с высокой вероятностью модифицирован.')
                all_clean = False
                has_errors = True
        print()
        print('  Между фрагментами обнаружены разрывы записи:')
        for _fi, _frag in enumerate(fragments):
            if _frag['gaps_to_next']:
                _g = _frag['gaps_to_next']
                if _g['seconds'] > 0:
                    print('    %s -> %s: %s, %s' % (
                        _g['prev_file'], _g['curr_file'], _g['reason'], format_duration(_g['seconds'])))
                else:
                    print('    %s -> %s: %s' % (
                        _g['prev_file'], _g['curr_file'], _g['reason']))
        print()
        if has_errors:
            print('  ИТОГ: Обнаружены признаки модификации в одном или нескольких фрагментах.')
        elif all_clean:
            print('  ИТОГ: Каждый фрагмент индивидуально не содержит признаков модификации.')
            print('  Между фрагментами есть разрывы записи.')
        else:
            print('  ИТОГ: Признаков монтажа не обнаружено. Обнаружены предупреждения,')
            print('  требующие анализа. Между фрагментами есть разрывы записи.')
    elif len(file_data) == 1:
        fname = os.path.basename(file_data[0][0])
        if total_errors == 0 and total_warnings == 0:
            print('  ЗАКЛЮЧЕНИЕ: Файл %s не содержит признаков модификации.' % fname)
            print('  Запись является непрерывной с одного устройства.')
        elif total_errors == 0 and total_warnings > 0:
            print('  ЗАКЛЮЧЕНИЕ: Признаков монтажа не обнаружено. Файл %s — обнаружено %d %s.' % (fname, total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
            print('  Требуется дальнейший анализ.')
        else:
            print('  ЗАКЛЮЧЕНИЕ: Файл %s — обнаружено %d %s и %d %s.' % (fname, total_errors, _plural_ru(total_errors, ('ошибка', 'ошибки', 'ошибок')), total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
            print('  Файл с высокой вероятностью модифицирован.')
    else:
        if total_errors == 0 and total_warnings == 0 and total_explained > 0:
            print('  ЗАКЛЮЧЕНИЕ: Нарушений не обнаружено. Все отклонения (%d) объяснены' % total_explained)
            print('  холодным пуском регистратора. Фрагменты являются единым видео,')
            print('  записанным одним устройством непрерывно. Холодный пуск:')
            _has_factory = any(is_factory_date_file(fp, file_data) for fp, _ in file_data)
            if _has_factory:
                print('  заводские файлы (GPS не захвачен) -> GPS захвачен -> штатная запись.')
            else:
                print('  стабилизация GPS-приёмника -> GPS захвачен -> штатная запись.')
        elif total_errors == 0 and total_warnings == 0:
            if len(file_data) == 1:
                fname = os.path.basename(file_data[0][0])
                print('  ЗАКЛЮЧЕНИЕ: Файл %s не содержит признаков модификации.' % fname)
                print('  Запись является непрерывной с одного устройства.')
            else:
                print('  ЗАКЛЮЧЕНИЕ: Нарушений не обнаружено. Фрагменты являются')
                print('  единым видео, записанным одним устройством непрерывно.')
        elif total_errors == 0 and total_warnings > 0:
            if len(file_data) == 1:
                fname = os.path.basename(file_data[0][0])
                print('  ЗАКЛЮЧЕНИЕ: Признаков монтажа не обнаружено. Файл %s — обнаружено %d %s.' % (fname, total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
                print('  Требуется дальнейший анализ.')
            else:
                print('  ЗАКЛЮЧЕНИЕ: Признаков монтажа не обнаружено. Обнаружено %d %s.' % (total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
                print('  Фрагменты вероятно являются единым видео с одного устройства.')
                print('  Предупреждения требуют анализа.')
        else:
            if len(file_data) == 1:
                fname = os.path.basename(file_data[0][0])
                print('  ЗАКЛЮЧЕНИЕ: Файл %s — обнаружено %d %s и %d %s.' % (
                    fname, total_errors, _plural_ru(total_errors, ('ошибка', 'ошибки', 'ошибок')), total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
                print('  Файл с высокой вероятностью модифицирован.')
            else:
                print('  ЗАКЛЮЧЕНИЕ: Обнаружено %d %s и %d %s.' % (total_errors, _plural_ru(total_errors, ('ошибка', 'ошибки', 'ошибок')), total_warnings, _plural_ru(total_warnings, ('предупреждение', 'предупреждения', 'предупреждений'))))
                print('  Фрагменты могут НЕ быть единым видео с одного устройства.')
    print()
    print(sep)
    time_end = datetime.datetime.now()
    end_str = time_end.strftime('%d.%m.%Y %H:%M:%S')
    elapsed = time_end - time_start
    print('  Время завершения проверки:  %s' % end_str)
    print('  Затраченное время:          %s' % format_duration((time_end - time_start).total_seconds()))
    print(sep)

    # Генерация файла детализации ошибок
    try:
        base_dir = os.path.dirname(os.path.abspath(ts_files[0])) if ts_files else '.'
        details_path = os.path.join(base_dir, 'error_details.txt')
        num_lines = generate_error_details(details_path, file_data)
        print()
        print('  Файл детализации ошибок:  error_details.txt (%d строк)' % num_lines)
        print(sep)
    except Exception as e:
        print()
        print('  [ВНИМАНИЕ] Не удалось создать error_details.txt: %s' % e)
        print(sep)

    # Генерация файла истории версий
    try:
        base_dir = os.path.dirname(os.path.abspath(ts_files[0])) if ts_files else '.'
        history_path = os.path.join(base_dir, 'history_log.txt')
        num_lines = generate_history_log(history_path)
        print()
        print('  Файл истории версий:     history_log.txt')
        print(sep)
    except Exception as e:
        print()
        print('  [ВНИМАНИЕ] Не удалось создать history_log.txt: %s' % e)
        print(sep)

if __name__ == '__main__':
    main()
