import requests
import dns.resolver
from scapy.all import IP, ICMP, Raw, send
import uuid
import time
import csv
from datetime import datetime
import os # ファイル操作用

# --- 設定 ---
LOG_FILE = "tx_traffic_log.csv"
TARGET_HTTP_SERVER = "example.com"  # HTTP/HTTPSターゲット
TARGET_DNS_SERVER = "8.8.8.8"      # MX VMのDNSサーバーIP (この場合はMX VMのens19 IP: 192.168.41.99など)
TARGET_ICMP_HOST = "8.8.8.8"       # ICMPターゲット (この場合はMX VMのens19 IP: 192.168.41.99など)

# VPNクライアントコマンド（SoftEther VPNクライアントのパスと接続設定に合わせる）
# 仮のパス。実際の環境に合わせて変更してください。
VPN_CLIENT_PATH = "/usr/local/vpnclient/vpncmd"
VPN_SERVER_NAME = "rx_vpn_server" # SoftEther VPN Client Managerで設定した接続名
VPN_SERVER_IP = "192.168.41.10" # RX VMのVPNサーバーのIPアドレス（ens20側ではない、TXから見えるIP）

# --- ログファイル初期化 ---
def init_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "protocol",
                "traffic_id",
                "vpn_status",
                "expected_protocol",
                "destination",
                "detail"
            ])

# --- ログ書き込み関数 ---
def write_log(protocol, traffic_id, vpn_status, expected_protocol, destination, detail=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # ミリ秒まで
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, protocol, traffic_id, vpn_status, expected_protocol, destination, detail])
    print(f"[{timestamp}] Logged: {protocol}, ID: {traffic_id}, VPN: {vpn_status}, Dest: {destination}")

# --- 各種通信関数 ---

def send_http(vpn_status):
    traffic_id = str(uuid.uuid4())
    url = f"http://{TARGET_HTTP_SERVER}/test_http?id={traffic_id}" # パケットIDをURLパラメータに含める
    try:
        response = requests.get(url, headers={"X-Traffic-ID": traffic_id}, timeout=5)
        detail = f"Status:{response.status_code}, Content-Length:{len(response.content)}"
        print(f"  HTTP GET Success: {url}")
    except requests.exceptions.RequestException as e:
        detail = f"HTTP GET Error: {e}"
        print(f"  HTTP GET Error: {e}")
    write_log("HTTP", traffic_id, vpn_status, "HTTP", url, detail)

def send_https(vpn_status):
    traffic_id = str(uuid.uuid4())
    url = f"https://{TARGET_HTTP_SERVER}/test_https?id={traffic_id}" # パケットIDをURLパラメータに含める
    try:
        response = requests.get(url, headers={"X-Traffic-ID": traffic_id}, timeout=5)
        detail = f"Status:{response.status_code}, Content-Length:{len(response.content)}"
        print(f"  HTTPS GET Success: {url}")
    except requests.exceptions.RequestException as e:
        detail = f"HTTPS GET Error: {e}"
        print(f"  HTTPS GET Error: {e}")
    write_log("HTTPS", traffic_id, vpn_status, "TLS", url, detail) # HTTPSはTLSとして識別されることを期待

def send_dns_query(vpn_status):
    traffic_id = str(uuid.uuid4())
    query_name = f"test-{traffic_id.replace('-', '')}.example.com" # ドメイン名にIDを埋め込む (ハイフン除去)
    try:
        # dnspython で特定のDNSサーバーにクエリ
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [TARGET_DNS_SERVER] # MX VMのIPアドレスを設定
        answers = resolver.resolve(query_name, 'A', lifetime=5)
        detail = f"DNS Query Success: {answers[0].address}"
        print(f"  DNS Query Success: {query_name}")
    except dns.resolver.NXDOMAIN:
        detail = f"DNS Query NXDOMAIN: {query_name}"
        print(f"  DNS Query NXDOMAIN: {query_name}")
    except dns.exception.Timeout:
        detail = f"DNS Query Timeout: {query_name}"
        print(f"  DNS Query Timeout: {query_name}")
    except Exception as e:
        detail = f"DNS Query Error: {e}"
        print(f"  DNS Query Error: {e}")
    write_log("DNS", traffic_id, vpn_status, "DNS", query_name, detail)

def send_icmp_ping(vpn_status):
    traffic_id = str(uuid.uuid4())
    # ICMPデータ部にIDを埋め込む (Rawペイロード)
    # ScapyのRawレイヤーで直接バイト列を埋め込む
    payload_data = f"PingTest-{traffic_id}"
    packet = IP(dst=TARGET_ICMP_HOST)/ICMP()/Raw(load=payload_data.encode())
    try:
        # verbose=0で詳細表示を抑制
        ans, unans = send(packet, count=1, timeout=5, verbose=0)
        # ans は(Request, Response)のタプルリスト。ここでは単純に送信できたかを確認
        if ans:
            detail = f"ICMP Echo Request Success: Response from {ans[0][1].src}"
            print(f"  ICMP Ping Success: {TARGET_ICMP_HOST}")
        else:
            detail = f"ICMP Echo Request Failed: No response from {TARGET_ICMP_HOST}"
            print(f"  ICMP Ping Failed: No response from {TARGET_ICMP_HOST}")
    except Exception as e:
        detail = f"ICMP Send Error: {e}"
        print(f"  ICMP Send Error: {e}")
    write_log("ICMP", traffic_id, vpn_status, "ICMP", TARGET_ICMP_HOST, detail)

# --- VPN接続/切断関数 (要実装) ---
import subprocess

def connect_vpn():
    print(f"\n--- Connecting VPN to {VPN_SERVER_NAME} ({VPN_SERVER_IP}) ---")
    try:
        # SoftEther VPNクライアントコマンド
        # 'accountconnect' コマンドで接続を開始
        # 実際には、VPN接続が確立するまで少し待つ必要があります。
        # 接続が完全に確立されたことを確認するロジックを追加することを推奨します。
        command = [VPN_CLIENT_PATH, "vpnclient", "exec", "accountconnect", VPN_SERVER_NAME]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
        # 接続確立を待つ（十分な時間を設定）
        time.sleep(10)
        print("VPN connection attempt completed. Please verify connection status manually if needed.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error connecting VPN: {e}")
        print(e.stderr)
        return False
    except FileNotFoundError:
        print(f"VPN client command not found at {VPN_CLIENT_PATH}. Please check the path.")
        return False

def disconnect_vpn():
    print(f"\n--- Disconnecting VPN from {VPN_SERVER_NAME} ---")
    try:
        command = [VPN_CLIENT_PATH, "vpnclient", "exec", "accountdisconnect", VPN_SERVER_NAME]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
        time.sleep(5) # 切断を待つ
        print("VPN disconnected.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error disconnecting VPN: {e}")
        print(e.stderr)
        return False
    except FileNotFoundError:
        print(f"VPN client command not found at {VPN_CLIENT_PATH}. Please check the path.")
        return False

# --- メイン実行部 ---
def main():
    init_log_file()
    print("Starting traffic generation...")

    # --- フェーズ1: VPNなしの通信 ---
    print("\n--- Phase 1: Traffic without VPN ---")
    for _ in range(2): # 各通信を複数回実行
        send_http("vpn_off")
        time.sleep(1)
        send_https("vpn_off")
        time.sleep(1)
        send_dns_query("vpn_off")
        time.sleep(1)
        send_icmp_ping("vpn_off")
        time.sleep(3) # 各サイクル間に少し間隔を空ける

    # --- フェーズ2: VPN接続 ---
    if connect_vpn():
        # --- フェーズ3: VPNありの通信 ---
        print("\n--- Phase 3: Traffic with VPN ---")
        for _ in range(2): # 各通信を複数回実行
            # VPN接続中は、トラフィックはVPNトンネル経由でMXに到達します。
            # ただし、ターゲットはインターネット上のものか、RX VMのプライベートIPになるはずです。
            # ここでは便宜上、同じターゲットを使います。
            send_http("vpn_on")
            time.sleep(1)
            send_https("vpn_on")
            time.sleep(1)
            send_dns_query("vpn_on")
            time.sleep(1)
            send_icmp_ping("vpn_on")
            time.sleep(3)

        # --- フェーズ4: VPN切断 ---
        disconnect_vpn()
    else:
        print("VPN connection failed, skipping VPN-enabled traffic phase.")

    print("\nTraffic generation finished. Log saved to tx_traffic_log.csv")

if __name__ == "__main__":
    # root権限が必要なScapyのsend()を使用するため、通常はsudoで実行します。
    # しかし、requestsやdnspythonはrootなしで動くため、実行環境によっては注意が必要です。
    # Linux環境であれば、scapyが依存するrawソケットはroot権限でしか開けないため、sudo python3 traffic_generator.py で実行してください。
    main()