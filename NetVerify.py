import os, sys, json, csv, re, ctypes, warnings, subprocess, time
from netmiko import ConnectHandler
from deepdiff import DeepDiff
from collections import defaultdict
from datetime import datetime

# Excel警告抑制
warnings.simplefilter("ignore", UserWarning)

try:
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

# --- カラー・定数設定 ---
YELLOW = '\033[33m'; RED = '\033[31m'; BLUE = '\033[36m'; GREEN = '\033[32m'; RESET = '\033[0m'
CLEAR_LINE = '\033[F\033[K'

if os.name == 'nt':
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except: pass

if getattr(sys, 'frozen', False): BASE_DIR = os.path.dirname(sys.executable)
else: BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SNAPSHOT_DIR, LOG_DIR = os.path.join(BASE_DIR, "snapshots"), os.path.join(BASE_DIR, "logs")

def ensure_dirs():
    """snapshots, logsフォルダが存在することを確認する"""
    for d in [SNAPSHOT_DIR, LOG_DIR]:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

# --- 機能関数 ---

def ping_check(ip):
    param = '-n' if os.name == 'nt' else '-c'
    cmd = ['ping', param, '1', '-w', '1000', ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except KeyboardInterrupt: raise
    except: return False

def trace_check(ip):
    print(f"    {BLUE}[INFO] Tracerouteを実行中... (h:15, w:1000ms){RESET}")
    if os.name == 'nt':
        cmd = ['tracert', '-d', '-w', '200', ip]
    else:
        cmd = ['traceroute', '-n', '-w', '0.2', ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='cp932' if os.name == 'nt' else 'utf-8')
        lines = res.stdout.splitlines()
        filtered = []
        for line in lines:
            l_s = line.strip()
            if not l_s or any(x in l_s for x in ["へのルートをトレースしています", "経由するホップ数は最大", "トレースを完了しました"]): continue
            filtered.append(line)
        return "\n".join(filtered)
    except KeyboardInterrupt: return f"{YELLOW}Tracerouteは中断されました。{RESET}"
    except Exception as e: return f"Traceroute失敗: {e}"

def find_teraterm():
    standard_paths = [r"C:\Program Files (x86)\teraterm\ttpmacro.exe", r"C:\Program Files\teraterm\ttpmacro.exe"]
    for p in standard_paths:
        if os.path.exists(p): return p
    try:
        result = subprocess.check_output('where /r C:\\ ttpmacro.exe', shell=True, stderr=subprocess.STDOUT)
        if result: return result.decode('cp932').splitlines()[0].strip()
    except: pass
    return None

def create_ttl_macro(host_info):
    h_name, ip = host_info.get('name'), host_info.get('ip')
    user, pw, en_pw = host_info.get('user'), host_info.get('pw'), host_info.get('en_pw')
    proto = str(host_info.get('protocol')).lower()
    
    macro_path = os.path.join(BASE_DIR, f"temp_{sanitize_filename(h_name)}.ttl")
    with open(macro_path, "w", encoding='cp932') as f:
        if proto == 'telnet':
            f.write(f"connect '{ip}:23 /nossh /T=1'\n")
        else:
            f.write(f"connect '{ip}:22 /ssh /2 /auth=password /user={user} /passwd={pw}'\n")
        
        f.write("pause 1\n")
        f.write("wait 'User Name:' 'Username:' 'login:' '>' '#'\n")
        f.write("if result = 1 or result = 2 or result = 3 then\n")
        f.write(f"  sendln '{user}'\n")
        f.write("  wait 'Password:' 'password:'\n")
        f.write(f"  sendln '{pw}'\n")
        f.write("  wait '>' '#'\n")
        f.write("endif\n")
        
        f.write("if result = 4 then\n")
        f.write("  sendln 'enable'\n")
        f.write("  waitregex '[Pp]assword|パスワード|暗号'\n")
        f.write(f"  sendln '{en_pw}'\n")
        f.write("  wait '#'\n")
        f.write("endif\n")
    return macro_path

def sanitize_filename(name):
    return re.sub(r'[\\/:*?"<>|]', '_', str(name))

def safe_parse_path(path):
    parts = re.findall(r"['\"]([^'\"]+)['\"]", path)
    cmd = parts[0] if len(parts) > 0 else "Unknown"
    sec = parts[1] if len(parts) > 1 else "Global"
    return cmd, sec

def format_val(val):
    if isinstance(val, dict): return " { " + ", ".join([f"{k}: {v}" for k, v in val.items()]) + " }"
    return str(val)

def restructure_data(data):
    if not isinstance(data, list): return data
    key_candidates = ['interface', 'intf', 'vlan_id', 'vlan', 'name', 'neighbor_id', 'pool_name', 'network']
    new_data = {}
    for item in data:
        if isinstance(item, dict):
            if 'network' in item:
                hop = item.get('nexthop_ip') or item.get('nexthop_if') or "direct"
                found_key = f"{item['network']}_via_{hop}"
            else:
                found_key = next((str(item[k]) for k in key_candidates if k in item), None)
            if found_key: new_data[found_key] = {k: v for k, v in item.items() if v != found_key}
            else: return data
        else: return data
    return new_data

def restructure_config(text):
    if not isinstance(text, str): return text
    sections = {"Global": []}
    current_section = "Global"
    ignore = ["Building configuration", "Current configuration", "Last configuration change", "ntp clock-period"]
    for line in text.splitlines():
        l_s = line.strip()
        if not l_s or l_s.startswith("!") or any(x in l_s for x in ignore): continue
        if not line.startswith(" "):
            current_section = l_s
            sections[current_section] = []
        else: sections[current_section].append(l_s)
    return sections

def load_hosts_flexible():
    hosts = []
    xlsx_path = os.path.join(BASE_DIR, "hosts.xlsx")
    if EXCEL_AVAILABLE and os.path.exists(xlsx_path):
        try:
            wb = openpyxl.load_workbook(xlsx_path, data_only=True); ws = wb.active
            headers = [str(cell.value).strip().lower() if cell.value else "" for cell in ws[1]]
            for row in ws.iter_rows(min_row=2, values_only=True):
                if not row or row[0] is None: continue
                h = {headers[i]: row[i] for i, name in enumerate(headers) if name and i < len(row)}
                h['en_pw'] = row[6] if len(row) > 6 else ""
                raw_cmds = row[7] if len(row) > 7 else ""
                h['command_list'] = [c.strip() for c in str(raw_cmds).replace('\r', '').split('\n') if c.strip()]
                hosts.append(h)
            return hosts
        except: pass
    return []

def show_mode_menu():
    print(f"\n{BLUE}====={RESET}\n   NetVerify \n{BLUE}====={RESET}")
    print(f"\n{YELLOW}[ モード選択 ]{RESET}\n0: 接続確認 (t:trace)\n1: ログイン\n2: ログ取得\n3: 解析・比較\n4: ログ+比較\nc: クリア\nq: 終了")

def main():
    tt_macro_exe = None
    mode_map = {"0": "接続確認", "0t": "接続確認(Trace付)", "1": "ログイン", "2": "ログ取得", "3": "解析・
