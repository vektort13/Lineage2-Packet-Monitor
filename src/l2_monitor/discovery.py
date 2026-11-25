"""Find the user's client process, its TCP endpoint and Npcap interfaces."""
import json
import ipaddress
import re
import subprocess
import sys
import winreg
import psutil
from pathlib import Path

from .live_state import load_profile


NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
WIRESHARK = 'C:/Program Files/Wireshark/'


def physical_up_guids():
    """Identify active PCI/USB adapters through Windows registry and psutil."""
    key_path = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    network_path = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    stats = psutil.net_if_stats()
    result = set()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, index)) as adapter:
                        guid = winreg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                        pnp_id = winreg.QueryValueEx(adapter, 'MatchingDeviceId')[0]
                    if not pnp_id.upper().startswith(('PCI\\', 'USB\\')):
                        continue
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        network_path + '\\' + guid + r'\Connection') as connection:
                        name = winreg.QueryValueEx(connection, 'Name')[0]
                    if name in stats and stats[name].isup:
                        result.add(guid.lower())
                except (OSError, ValueError):
                    continue
    except OSError:
        pass
    return result


def processes():
    result = []
    profile_name = load_profile()['process_name'].lower()
    for process in psutil.process_iter(['pid', 'name', 'create_time']):
        if (process.info['name'] or '').lower() not in ('asteriosgame.exe', 'l2.exe', profile_name):
            continue
        try:
            connections = [dict(local_ip=c.laddr.ip, local_port=c.laddr.port,
                                remote_ip=c.raddr.ip, remote_port=c.raddr.port)
                           for c in process.net_connections(kind='tcp')
                           if c.status == psutil.CONN_ESTABLISHED and c.raddr]
            result.append(dict(pid=process.pid, name=process.info['name'], exe=process.exe(),
                               create_time=process.info['create_time'], connections=connections,
                               profile_candidate=process.info['name'].lower() == profile_name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result


def select_process(pid=None):
    profile = load_profile()
    choices = [p for p in processes() if pid is None or p['pid'] == pid]
    connected = []
    for process in choices:
        connections = process['connections']
        # Known game ports disambiguate auxiliary connections, but are never
        # required: a lone established connection works on any custom port.
        preferred = [c for c in connections if c['remote_port'] in (profile['game_port'], 7777)]
        connected.extend((process, c) for c in (preferred or connections))
    if not connected:
        raise ValueError('Ожидание игрового клиента с установленным TCP-соединением')
    if len(connected) > 1:
        pids = {p['pid'] for p, _ in connected}
        if len(pids) > 1:
            raise ValueError('Найдено несколько клиентов: выберите PID в панели')
        raise ValueError('У клиента несколько TCP-соединений; игровое соединение неоднозначно')
    return connected[0]


def interfaces():
    try:
        from .npcap import interfaces as native_interfaces
        choices = native_interfaces()
    except OSError:
        if getattr(sys, 'frozen', False) or not Path(WIRESHARK + 'dumpcap.exe').exists():
            raise
        output = subprocess.run([WIRESHARK + 'dumpcap.exe', '-D'], capture_output=True,
                                check=True, timeout=10, creationflags=NO_WINDOW).stdout.decode('utf-8', 'replace')
        choices=[]
        for line in output.splitlines():
            match=re.match(r'^(\d+)\. (\S+) \((.*)\)$',line)
            if match:
                number,device,name=match.groups()
                choices.append(dict(id=number,device=device,name=name,recommended=False))
    physical = physical_up_guids()
    addresses = psutil.net_if_addrs()
    network_path = r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    for item in choices:
        item['recommended']=any(guid in item['device'].lower() for guid in physical)
        item['addresses'] = []
        guid = re.search(r'\{[^{}]+\}$', item['device'])
        if guid:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, network_path + '\\' + guid.group() + r'\Connection') as key:
                    name = winreg.QueryValueEx(key, 'Name')[0]
                item['addresses'] = [entry.address for entry in addresses.get(name, [])]
            except OSError:
                pass
    return choices


def select_interface(requested='auto', endpoint=None):
    choices = interfaces()
    if requested != 'auto':
        matches = [x for x in choices if requested in (x['id'], x['device'])]
    elif endpoint and (ipaddress.ip_address(endpoint['remote_ip']).is_loopback
                       or endpoint['remote_ip'] == endpoint['local_ip']):
        matches = [x for x in choices if 'loopback' in (x['device'] + ' ' + x['name']).lower()]
    elif endpoint and any(endpoint['local_ip'] in x.get('addresses', []) for x in choices):
        matches = [x for x in choices if endpoint['local_ip'] in x.get('addresses', [])]
    else:
        matches = [x for x in choices if x['recommended']]
        if not matches:
            matches = [x for x in choices if 'loopback' not in x['device'].lower()]
    if len(matches) != 1:
        raise ValueError('Выберите интерфейс захвата: автоматический выбор неоднозначен')
    return matches[0]
