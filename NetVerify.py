import os, sys, json, csv, re, ctypes, warnings, subprocess, time
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
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
    """フォルダが存在しない場合に作成する"""
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
        cmd = ['tracert', '-d', '-h', '15', '-w', '1000', ip]
    else:
        cmd = ['traceroute', '-n', '-m', '15', '-w', '1', ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='cp932' if os.name == 'nt' else 'utf-8')
        lines = res.stdout.splitlines()
        filtered = []
        for line in lines:
            l_s = line.strip()
            if not l_s or any(x in l_s for x in ["トレースしています", "ホップ数は最大", "完了しました"]): continue
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
    """C1200等の2段階ログインに対応したログインマクロ(※変更なし)"""
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
        f.write("if result >= 1 and result <= 3 then\n")
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
    print(f"\n{YELLOW}[ モード選択 ]{RESET}\n0: 接続確認 (t:traceも実施)\n1: ログイン\n2: ログ取得\n3: 解析・比較\n4: ログ+比較\nc: クリア\nq: 終了")

def main():
    tt_macro_exe = None
    mode_map = {"0": "接続確認", "0t": "接続確認(Trace付)", "1": "ログイン", "2": "ログ取得", "3": "解析・比較", "4": "ログ+比較"}
    show_mode_menu()
    while True:
        try:
            mode_in = input("選択: ").lower().strip()
            if not mode_in: sys.stdout.write(CLEAR_LINE); continue
            if mode_in == 'q': break
            if mode_in == 'c': os.system('cls' if os.name == 'nt' else 'clear'); show_mode_menu(); continue
            if mode_in not in mode_map: sys.stdout.write(CLEAR_LINE); continue
        except (KeyboardInterrupt, EOFError): sys.exit(0)

        while True:
            hosts = load_hosts_flexible()
            if not hosts: break
            
            # リスト複製防止：一度だけ表示
            print(f"\n{YELLOW}[ 対象一覧 - モード: {mode_map[mode_in]} ]{RESET}")
            for i, h in enumerate(hosts): print(f"{i}: {h.get('name')} ({h.get('ip')})")
            
            indices = []
            while True:
                try:
                    choice = input(f"番号 (all/0.../b): ").lower().strip()
                    if choice == 'b': break
                    if not choice: sys.stdout.write(CLEAR_LINE); continue
                    indices = range(len(hosts)) if choice == 'all' else [int(i.strip()) for i in choice.split(',') if i.strip().isdigit() and int(i.strip()) < len(hosts)]
                    if indices: break
                    else: sys.stdout.write(CLEAR_LINE)
                except (KeyboardInterrupt, EOFError): break

            if choice == 'b': # メニューに戻る
                show_mode_menu()
                break

            # --- 処理実行セクション ---
            try:
                if mode_in in ['0', '0t']:
                    for idx in indices:
                        host = hosts[idx]; ip = host.get('ip')
                        res = ping_check(ip)
                        status = f"{GREEN}[SUCCESS]{RESET}" if res else f"{RED}[FAIL]{RESET}"
                        print(f"  \n{status} {host.get('name')} ({ip})")
                        if mode_in == '0t':
                            trace_result = trace_check(ip)
                            print(f"    [Trace Result]\n{trace_result}\n\n")
                    continue

                if mode_in == '1':
                    if not tt_macro_exe: tt_macro_exe = find_teraterm()
                    if not tt_macro_exe: print(f"{RED}[!] ttpmacro.exeが見つかりません。{RESET}")
                    else:
                        for idx in indices:
                            host = hosts[idx]
                            print(f"  {GREEN}>>> TeraTerm起動: {host.get('name')}{RESET}")
                            ttl = create_ttl_macro(host)
                            subprocess.Popen([tt_macro_exe, ttl])
                            time.sleep(0.5); 
                            try: os.remove(ttl)
                            except: pass
                    continue

                ensure_dirs()
                today = datetime.now().strftime("%Y%m%d")
                for i, idx in enumerate(indices):
                    host = hosts[idx]; h_name, ip = str(host.get('name')), host.get('ip')
                    h_file, target_commands = sanitize_filename(h_name), host.get('command_list', [])
                    v_base = host.get('vendor', 'cisco_ios')
                    v_proto = '_telnet' if str(host.get('protocol')).lower() == 'telnet' else ''
                    
                    device = { 
                        'device_type': f"{v_base}{v_proto}", 'host': ip, 
                        'username': host.get('user'), 'password': host.get('pw'), 
                        'secret': host.get('en_pw'), 'global_delay_factor': 2
                    }

                    print("\n\n\n\n\n" + "=" * 70); print(f"{GREEN}>>> [{h_name}]{RESET}")
                    net = None
                    try:
                        try:
                            net = ConnectHandler(**device)
                        except NetmikoAuthenticationException as e:
                            # C1200救済ロジック：genericドライバを使用（修正済み）
                            if "allowed types" in str(e) or "authentication type" in str(e).lower():
                                print(f"  {YELLOW}[INFO] 特殊な認証を検知しました。C1200モードで再試行します...{RESET}")
                                device['password'] = '' 
                                device['device_type'] = 'generic' # リストに実在する汎用ドライバに変更
                                net = ConnectHandler(**device)
                            else: raise

                        # 画面上のログインプロンプトに応答
                        for _ in range(3):
                            buf = net.read_channel()
                            if any(x in buf for x in ['User Name:', 'Username:', 'login:']):
                                net.write_channel(host.get('user') + '\n')
                                time.sleep(1)
                            elif any(x in buf for x in ['Password:', 'password:']):
                                net.write_channel(host.get('pw') + '\n')
                                time.sleep(1)
                            else: break
                        
                        if ">" in net.find_prompt(): net.enable()
                        
                        current_data, log_body, search_hits = {}, f"\n! --- Append Log: {datetime.now()} ---\n! Device: {h_name}\n\n", defaultdict(list)
                        for cmd in target_commands:
                            print(f"  - {cmd}"); raw_out = net.send_command(cmd, strip_prompt=False, strip_command=False)
                            log_body += f"{raw_out}\n\n"
                            
                            s_path = os.path.join(BASE_DIR, "search.txt")
                            if os.path.exists(s_path):
                                with open(s_path, "r", encoding='utf-8') as f: keywords = [l.strip() for l in f if l.strip()]
                                for kw in keywords:
                                    for line in raw_out.splitlines():
                                        if kw.lower() in line.lower():
                                            hi = re.sub(re.escape(kw), lambda m: f"{YELLOW}{m.group()}{RESET}", line.strip(), flags=re.IGNORECASE)
                                            search_hits[kw].append(f"[{cmd}] {hi}")

                            if mode_in in ['3', '4']:
                                try:
                                    parsed = net.send_command(cmd, use_textfsm=True)
                                    current_data[cmd] = restructure_config(parsed) if "running-config" in cmd else restructure_data(parsed)
                                except: current_data[cmd] = raw_out
                        
                        if search_hits:
                            print(f"\n{YELLOW}[ 検索結果 ]{RESET}"); [print(f"▼ '{YELLOW}{k}{RESET}':\n" + "\n".join(v)) for k, v in search_hits.items()]

                        if mode_in in ['2', '4']:
                            log_path = os.path.join(LOG_DIR, f"{h_file}_{today}.log")
                            with open(log_path, "a", encoding='utf-8') as f: f.write(log_body)
                            print(f"  {BLUE}[Log] logs/{h_file}_{today}.log (Append){RESET}")
                        
                        if mode_in in ['3', '4']:
                            snap_p = os.path.join(SNAPSHOT_DIR, f"snapshot_{h_file}.json")
                            if os.path.exists(snap_p):
                                with open(snap_p, "r", encoding='utf-8') as f: old_data = json.load(f)
                                diff = DeepDiff(old_data, current_data, ignore_order=True)
                                if diff: print(f"\n{YELLOW}== 差分検出 =={RESET}\n{diff}")
                                else: print(f"  {GREEN}[OK] 差分なし{RESET}")
                                os.rename(snap_p, os.path.join(SNAPSHOT_DIR, f"snapshot_{h_file}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"))
                            with open(snap_p, "w", encoding='utf-8') as f: json.dump(current_data, f, indent=4, ensure_ascii=False)
                    
                    except Exception as e: print(f"  {RED}[!] エラー: {e}{RESET}")
                    finally:
                        if net: net.disconnect()
                    if i == len(indices) - 1: print("\n" + "=" * 70)
            
            except KeyboardInterrupt: print(f"\n{YELLOW}[CANCEL] 中断されました。機器一覧に戻ります。{RESET}")
            print("")

if __name__ == "__main__":
    try: main()
    except (KeyboardInterrupt, EOFError): sys.exit(0)
