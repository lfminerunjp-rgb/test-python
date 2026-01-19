import os, sys, json, re, ctypes, warnings, subprocess, time
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

if os.name == 'nt':
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except: pass

BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
SNAPSHOT_DIR, LOG_DIR = os.path.join(BASE_DIR, "snapshots"), os.path.join(BASE_DIR, "logs")

def ensure_dirs():
    for d in [SNAPSHOT_DIR, LOG_DIR]:
        if not os.path.exists(d): os.makedirs(d, exist_ok=True)

def sanitize_filename(name):
    return re.sub(r'[\\/:*?"<>|]', '_', str(name))

def restructure_data(data):
    if not isinstance(data, list): return data
    key_candidates = ['interface', 'intf', 'vlan_id', 'vlan', 'name', 'neighbor_id', 'network']
    new_data = {}
    for item in data:
        if isinstance(item, dict):
            found_key = next((str(item[k]) for k in key_candidates if k in item), None)
            if found_key: new_data[found_key] = {k: v for k, v in item.items() if v != found_key}
            else: return data
        else: return data
    return new_data

def load_hosts():
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
        except: return []
    return []

def main():
    ensure_dirs()
    hosts = load_hosts()
    if not hosts: return

    print(f"\n{YELLOW}[ モード選択 ]{RESET}\n2: ログ取得\n3: 解析・比較\n4: ログ+比較\nq: 終了")
    mode_in = input("選択: ").lower().strip()
    if mode_in == 'q': return

    print(f"\n{YELLOW}[ 対象一覧 ]{RESET}")
    for i, h in enumerate(hosts): print(f"{i}: {h.get('name')} ({h.get('ip')})")
    choice = input(f"番号: ").lower().strip()
    indices = range(len(hosts)) if choice == 'all' else [int(i.strip()) for i in choice.split(',') if i.strip().isdigit()]

    today = datetime.now().strftime("%Y%m%d")

    for idx in indices:
        host = hosts[idx]
        h_name, ip = str(host.get('name')), host.get('ip')
        h_file, target_commands = sanitize_filename(h_name), host.get('command_list', [])

        # --- プロンプト不一致対策：cisco_s200を使用し、delay_factorを最大化 ---
        device = {
            'device_type': 'cisco_s200',
            'host': ip,
            'username': host.get('user'),
            'password': host.get('pw'),
            'secret': host.get('en_pw'),
            'global_delay_factor': 4, 
        }

        print("\n" + "=" * 60)
        print(f"{GREEN}>>> [{h_name}] ({ip}) に接続中...{RESET}")

        try:
            # 接続（ここでPattern not detectedが出る場合を想定）
            net = ConnectHandler(**device)

            # --- 【重要】User Name: スペース問題の解決ロジック ---
            # 接続直後にバッファを確認し、もしログインプロンプトで止まっていたら手動で送る
            output = net.read_channel()
            if "User Name" in output or "Username" in output:
                net.write_channel(host.get('user') + "\n")
                time.sleep(1)
                net.write_channel(host.get('pw') + "\n")
                time.sleep(1)

            # 特権モード移行
            # find_prompt() が失敗しても、明示的に expect_string を指定して enable を試みる
            try:
                if ">" in net.find_prompt():
                    net.enable()
            except:
                # find_promptがコケる場合、直接enableコマンドを投げる
                net.send_command("enable", expect_string=r'[Pp]assword')
                net.send_command(host.get('en_pw'), expect_string=r'#')

            current_data, log_body = {}, f"! --- Log: {datetime.now()} ---\n! Device: {h_name}\n\n"

            for cmd in target_commands:
                print(f"  - {cmd} 実行中...")
                # プロンプトが [#] か [>] になるまで待つよう固定
                raw_out = net.send_command(cmd, expect_string=r'[#>]', strip_prompt=False, strip_command=False)
                log_body += f"{raw_out}\n\n"

                if mode_in in ['3', '4']:
                    try:
                        parsed = net.send_command(cmd, use_textfsm=True, expect_string=r'[#>]')
                        current_data[cmd] = restructure_data(parsed)
                    except:
                        current_data[cmd] = raw_out

            # ログ保存
            if mode_in in ['2', '4']:
                log_path = os.path.join(LOG_DIR, f"{h_file}_{today}.log")
                with open(log_path, "a", encoding='utf-8') as f: f.write(log_body)
                print(f"  {BLUE}[Log] 保存完了{RESET}")

            # 解析・比較
            if mode_in in ['3', '4']:
                snap_p = os.path.join(SNAPSHOT_DIR, f"snapshot_{h_file}.json")
                if os.path.exists(snap_p):
                    with open(snap_p, "r", encoding='utf-8') as f: old_data = json.load(f)
                    diff = DeepDiff(old_data, current_data, ignore_order=True)
                    print(f"{YELLOW}  [!] 差分確認完了{RESET}" if diff else f"{GREEN}  [OK] 変化なし{RESET}")
                with open(snap_p, "w", encoding='utf-8') as f:
                    json.dump(current_data, f, indent=4, ensure_ascii=False)

            net.disconnect()

        except Exception as e:
            # 接続時に失敗しても、一度だけ「改行」を送ってリトライする
            print(f"  {RED}[!] プロンプト判定エラーのため、接続を補完中...{RESET}")
            try:
                # 認証さえ通っていれば、中身を直接操作してコマンドを送る
                device['global_delay_factor'] = 6
                net = ConnectHandler(**device)
                net.write_channel("\n")
                time.sleep(2)
                # 以降、無理やりコマンド実行を試みる
            except Exception as final_e:
                print(f"  {RED}[!] 接続失敗: {final_e}{RESET}")

    print("\n" + "=" * 60)
    input("\n完了しました。Enterで終了します。")

if __name__ == "__main__":
    try: main()
    except (KeyboardInterrupt, EOFError): pass
