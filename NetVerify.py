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
    for d in [SNAPSHOT_DIR, LOG_DIR]:
        if not os.path.exists(d): os.makedirs(d, exist_ok=True)

# --- 機能関数 ---

def ping_check(ip):
    param = '-n' if os.name == 'nt' else '-c'
    cmd = ['ping', param, '1', '-w', '1000', ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except: return False

def trace_check(ip):
    print(f"    {BLUE}[INFO] Tracerouteを実行中...{RESET}")
    cmd = ['tracert', '-d', '-w', '200', ip] if os.name == 'nt' else ['traceroute', '-n', '-w', '1', ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='cp932' if os.name == 'nt' else 'utf-8')
        return res.stdout
    except: return "Traceroute失敗"

def sanitize_filename(name):
    return re.sub(r'[\\/:*?"<>|]', '_', str(name))

def safe_parse_path(path):
    parts = re.findall(r"['\"]([^'\"]+)['\"]", path)
    return (parts[0] if len(parts) > 0 else "Unknown"), (parts[1] if len(parts) > 1 else "Global")

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
    sections = {"Global": []}; current_section = "Global"
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
    print(f"\n{BLUE}====={RESET}\n   NetVerify (C1200 Expert Fix)\n{BLUE}====={RESET}")
    print(f"\n{YELLOW}[ モード選択 ]{RESET}\n0: 接続確認\n2: ログ取得\n3: 解析・比較\n4: ログ+比較\nc: クリア\nq: 終了")

def main():
    mode_map = {"0": "接続確認", "2": "ログ取得", "3": "解析・比較", "4": "ログ+比較"}
    show_mode_menu()
    while True:
        try:
            mode_in = input("選択: ").lower().strip()
            if mode_in == 'q': break
            if mode_in == 'c': os.system('cls' if os.name == 'nt' else 'clear'); show_mode_menu(); continue
            if mode_in not in mode_map: continue

            hosts = load_hosts_flexible()
            if not hosts: continue
            
            print(f"\n{YELLOW}[ 対象一覧 ]{RESET}")
            for i, h in enumerate(hosts): print(f"{i}: {h.get('name')} ({h.get('ip')})")
            
            choice = input(f"番号: ").lower().strip()
            indices = range(len(hosts)) if choice == 'all' else [int(i.strip()) for i in choice.split(',') if i.strip().isdigit()]
            
            ensure_dirs()
            today = datetime.now().strftime("%Y%m%d")

            for idx in indices:
                host = hosts[idx]; h_name, ip = str(host.get('name')), host.get('ip')
                h_file, target_commands = sanitize_filename(h_name), host.get('command_list', [])
                
                # --- C1200 決定版設定 ---
                device = { 
                    'device_type': 'cisco_s200', # 認証を通すために必須
                    'host': ip, 'username': host.get('user'), 'password': host.get('pw'), 
                    'secret': host.get('en_pw'), 
                    'global_delay_factor': 2,
                    'session_preparation': False, # 【重要】接続直後のプロンプト自動判定をスキップ
                }

                print("\n" + "=" * 70); print(f"{GREEN}>>> [{h_name}] に接続中...{RESET}")
                try:
                    with ConnectHandler(**device) as net:
                        # 自動初期化をスキップしたため、手動でプロンプトを出す
                        time.sleep(1)
                        net.write_channel("\n")
                        time.sleep(1)
                        
                        # 特権モード移行
                        net.write_channel("enable\n")
                        time.sleep(1)
                        out = net.read_channel()
                        if "Password" in out or "password" in out:
                            net.write_channel(host.get('en_pw') + "\n")
                            time.sleep(1)

                        # ページング無効化
                        net.send_command("terminal datadump", expect_string=r'[#>]')

                        current_data, log_body = {}, f"\n! --- Log: {datetime.now()} ---\n! Device: {h_name}\n\n"
                        
                        for cmd in target_commands:
                            print(f"  - {cmd}")
                            # Netmikoの判定を無視して、# か > が出るまで待つ
                            raw_out = net.send_command(cmd, expect_string=r'[#>]', strip_prompt=False, strip_command=False)
                            log_body += f"{raw_out}\n\n"

                            if mode_in in ['3', '4']:
                                try:
                                    parsed = net.send_command(cmd, use_textfsm=True, expect_string=r'[#>]')
                                    current_data[cmd] = restructure_config(parsed) if "running-config" in cmd else restructure_data(parsed)
                                except: current_data[cmd] = raw_out
                        
                        # ログ保存
                        if mode_in in ['2', '4']:
                            with open(os.path.join(LOG_DIR, f"{h_file}_{today}.log"), "a", encoding='utf-8') as f: f.write(log_body)
                            print(f"  {BLUE}[Log] 保存完了{RESET}")
                        
                        # 比較処理
                        if mode_in in ['3', '4']:
                            snap_p = os.path.join(SNAPSHOT_DIR, f"snapshot_{h_file}.json")
                            if os.path.exists(snap_p):
                                with open(snap_p, "r", encoding='utf-8') as f: old_data = json.load(f)
                                diff = DeepDiff(old_data, current_data, ignore_order=True)
                                if diff: print(f"{YELLOW}  [!] 差分あり{RESET}")
                                else: print(f"{GREEN}  [OK] 差分なし{RESET}")
                                os.rename(snap_p, os.path.join(SNAPSHOT_DIR, f"old_snapshot_{h_file}_{datetime.now().strftime('%H%M%S')}.json"))
                            with open(snap_p, "w", encoding='utf-8') as f: json.dump(current_data, f, indent=4, ensure_ascii=False)

                except Exception as e: print(f"  {RED}[!] エラー: {e}{RESET}")
            print("\n" + "=" * 70)
        except KeyboardInterrupt: break

if __name__ == "__main__":
    main()
