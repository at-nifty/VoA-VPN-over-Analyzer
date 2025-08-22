import requests
import dns.resolver
from scapy.all import IP, ICMP, Raw, send, conf # scapy.all を使用
import uuid
import time
import csv
from datetime import datetime
import os
import subprocess
import re

# --- 設定 ---
LOG_FILE = "tx_traffic_log.csv"
TARGET_HTTP_SERVER = "example.com"  # HTTP/HTTPSターゲット
TARGET_DNS_SERVER = "8.8.8.8"      # DNSクエリのターゲットDNSサーバー (インターネット上のパブリックDNSが適切)
TARGET_ICMP_HOST = "8.8.8.8"       # ICMPターゲット (インターネット上のパブリックIPが適切)

# TX VMのNIC名 (お使いの環境に合わせて正確なNIC名を指定)
PHYSICAL_NIC = "ens18" # 例: eth0, enp0s3など、TX VMの物理NIC名
VPN_VIRTUAL_NIC = "vpn_vpn01" # 例: se0, tap_softetherなど、SoftEther VPNが作成する仮想NIC名

# --- ログファイル初期化 ---
def init_log_file():
    """ログファイルを初期化し、ヘッダーを書き込む"""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "protocol",
                "traffic_id",
                "send_nic",
                "expected_protocol",
                "destination",
                "detail"
            ])

# --- ログ書き込み関数 ---
def write_log(protocol, traffic_id, send_nic, expected_protocol, destination, detail=""):
    """通信情報をログファイルに追記する"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, protocol, traffic_id, send_nic, expected_protocol, destination, detail])
    print(f"[{timestamp}] Logged: {protocol}, ID: {traffic_id}, NIC: {send_nic}, Dest: {destination}")

# --- ヘルパー関数: インターフェースのIPアドレスを取得 ---
def get_interface_ip(iface_name):
    """指定されたインターフェースのIPv4アドレスを取得する"""
    try:
        result = subprocess.run(['ip', 'addr', 'show', iface_name], capture_output=True, text=True, check=True)
        match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        print(f"Error getting IP for {iface_name}: {e}")
        return None

# --- 各種通信関数 ---

def send_http(send_nic_name):
    """HTTP GETリクエストを送信し、パケットIDをヘッダーとURLに埋め込む"""
    traffic_id = str(uuid.uuid4())
    url = f"http://{TARGET_HTTP_SERVER}/test_http?id={traffic_id}"
    
    source_ip = get_interface_ip(send_nic_name)
    if not source_ip:
        write_log("HTTP", traffic_id, send_nic_name, "HTTP", url, "Error: Could not get source IP for NIC.")
        return

    requests_args = {"headers": {"X-Traffic-ID": traffic_id}, "timeout": 10} # カスタムヘッダーでIDを付与
    requests_args["source_address"] = (source_ip, 0) # 送信元IPアドレスをバインド

    try:
        print(f"  Sending HTTP from {send_nic_name} ({source_ip}) to {TARGET_HTTP_SERVER}")
        response = requests.get(url, **requests_args)
        detail = f"Status:{response.status_code}, Content-Length:{len(response.content)}"
        print(f"  HTTP GET Success: {url}")
    except requests.exceptions.RequestException as e:
        detail = f"HTTP GET Error: {e}"
        print(f"  HTTP GET Error: {e}")
    write_log("HTTP", traffic_id, send_nic_name, "HTTP", url, detail)

def send_https(send_nic_name):
    """HTTPS GETリクエストを送信し、パケットIDをヘッダーとURLに埋め込む"""
    traffic_id = str(uuid.uuid4())
    url = f"https://{TARGET_HTTP_SERVER}/test_https?id={traffic_id}" # URLパラメータにIDを含める
    
    source_ip = get_interface_ip(send_nic_name)
    if not source_ip:
        write_log("HTTPS", traffic_id, send_nic_name, "TLS", url, "Error: Could not get source IP for NIC.")
        return

    requests_args = {"headers": {"X-Traffic-ID": traffic_id}, "timeout": 10} # カスタムヘッダーでIDを付与
    requests_args["source_address"] = (source_ip, 0) # 送信元IPアドレスをバインド

    try:
        print(f"  Sending HTTPS from {send_nic_name} ({source_ip}) to {TARGET_HTTP_SERVER}")
        response = requests.get(url, **requests_args)
        detail = f"Status:{response.status_code}, Content-Length:{len(response.content)}"
        print(f"  HTTPS GET Success: {url}")
    except requests.exceptions.RequestException as e:
        detail = f"HTTPS GET Error: {e}"
        print(f"  HTTPS GET Error: {e}")
    write_log("HTTPS", traffic_id, send_nic_name, "TLS", url, detail) # HTTPSはTLSとして識別されることを期待

def send_dns_query(send_nic_name):
    """DNS Aレコードクエリを送信し、パケットIDをドメイン名に埋め込む"""
    traffic_id = str(uuid.uuid4())
    # ドメイン名にIDを埋め込む (ハイフンを除去してDNSの命名規則に合わせる)
    query_name = f"test-{traffic_id.replace('-', '')}.example.com"
    
    source_ip = get_interface_ip(send_nic_name)
    if not source_ip:
        write_log("DNS", traffic_id, send_nic_name, "DNS", query_name, "Error: Could not get source IP for NIC.")
        return

    # dnspython で特定のDNSサーバーにクエリ
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [TARGET_DNS_SERVER]
    
    # dnspython で送信元IPを直接バインドする公式な方法はないため、
    # OSが source_ip に基づいてルーティングすることを期待。
    # 厳密なバインドが必要な場合は、socketモジュールを直接使用する。

    try:
        print(f"  Sending DNS query from {send_nic_name} ({source_ip}) for {query_name} to {TARGET_DNS_SERVER}")
        answers = resolver.resolve(query_name, 'A', lifetime=10) # タイムアウトを少し長めに
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
    write_log("DNS", traffic_id, send_nic_name, "DNS", query_name, detail)

def send_icmp_ping(send_nic_name):
    """ICMP Echo Requestを送信し、パケットIDをデータ部に埋め込む"""
    traffic_id = str(uuid.uuid4())
    # ICMPデータ部にIDを埋め込む (Rawペイロード)
    payload_data = f"PingTest-{traffic_id}"
    packet = IP(dst=TARGET_ICMP_HOST)/ICMP()/Raw(load=payload_data.encode())
    
    try:
        print(f"  Sending ICMP from {send_nic_name} to {TARGET_ICMP_HOST}")
        # Scapyのsend()のiface引数でNICを直接指定
        ans, unans = send(packet, count=1, timeout=5, verbose=0, iface=send_nic_name)
        if ans:
            detail = f"ICMP Echo Request Success: Response from {ans[0][1].src}"
            print(f"  ICMP Ping Success: {TARGET_ICMP_HOST}")
        else:
            detail = f"ICMP Echo Request Failed: No response from {TARGET_ICMP_HOST}"
            print(f"  ICMP Ping Failed: No response from {TARGET_ICMP_HOST}")
    except Exception as e:
        detail = f"ICMP Send Error from {send_nic_name}: {e}"
        print(f"  ICMP Send Error from {send_nic_name}: {e}")
    write_log("ICMP", traffic_id, send_nic_name, "ICMP", TARGET_ICMP_HOST, detail)

# --- メイン実行部 ---
def main():
    init_log_file()
    print("Starting traffic generation in constant VPN connection mode...")

    # 事前確認のメッセージ
    print(f"\n--- IMPORTANT ---")
    print(f"1. Please ensure SoftEther VPN client is CONNECTED and {VPN_VIRTUAL_NIC} NIC is active and has an IP address.")
    print(f"2. Confirm {PHYSICAL_NIC} also has its IP address.")
    print(f"   (You can use 'ip a' command on TX VM to check NIC names and IPs)")
    print(f"3. Depending on your OS routing, you might need specific routes for {PHYSICAL_NIC} to reach internet traffic directly while VPN is ON.")
    print(f"   (e.g., policy routing or specific static routes)")
    print(f"--- IMPORTANT ---\n")
    time.sleep(5) # ユーザーがメッセージを読むための待機時間

    # 送信する通信とNICの組み合わせを定義
    # ここで送りたいプロトコルと送信NICの組み合わせを記述。
    traffic_scenarios = [
        (send_http, PHYSICAL_NIC, "HTTP (Direct)"),
        (send_https, PHYSICAL_NIC, "HTTPS (Direct)"),
        (send_dns_query, PHYSICAL_NIC, "DNS (Direct)"),
        (send_icmp_ping, PHYSICAL_NIC, "ICMP (Direct)"),
        
        (send_http, VPN_VIRTUAL_NIC, "HTTP (via VPN)"),
        (send_https, VPN_VIRTUAL_NIC, "HTTPS (via VPN)"),
        (send_dns_query, VPN_VIRTUAL_NIC, "DNS (via VPN)"),
        (send_icmp_ping, VPN_VIRTUAL_NIC, "ICMP (via VPN)"),
    ]

    for cycle in range(2):
        print(f"\n--- Traffic Generation Cycle {cycle + 1} ---")
        for func, nic, description in traffic_scenarios:
            print(f"  Executing: {description} via {nic}")
            func(nic)
            time.sleep(2)

    print("\nTraffic generation finished. Log saved to tx_traffic_log.csv")

if __name__ == "__main__":
    main()
