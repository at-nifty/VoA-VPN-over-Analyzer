# parse_zeek_logs.py
import pandas as pd
import json
import re
import os

# Zeekログファイルのパス設定 (環境に合わせて要修正)
# 例: /opt/zeek/logs/current/
ZEEK_LOG_DIR = "/opt/zeek/logs/current/"

def parse_zeek_log_json(log_filename):
    """ZeekのJSON形式ログファイルをパースしてDataFrameを返す"""
    log_path = os.path.join(ZEEK_LOG_DIR, log_filename)
    if not os.path.exists(log_path):
        print(f"Warning: Zeek log file not found: {log_path}")
        return pd.DataFrame()
    
    records = []
    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('#'): # コメント行はスキップ
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Skipping malformed JSON line in {log_path}: {line.strip()}")
                continue
    return pd.DataFrame(records)

def extract_packet_id_from_zeek():
    """
    Zeekの各種ログからパケットIDとZeekのプロトコル識別結果を抽出する。
    """
    # 各種Zeekログをパース
    df_conn = parse_zeek_log_json("conn.log")
    df_http = parse_zeek_log_json("http.log")
    df_dns = parse_zeek_log_json("dns.log")
    df_ssl = parse_zeek_log_json("ssl.log")
    df_icmp_custom = parse_zeek_log_json("icmp_id_log.log") # カスタムICMPログ

    results = []

    # HTTPログからの抽出
    if not df_http.empty:
        # request_headersが辞書型であることを期待し、'x_traffic_id'を抽出
        df_http['traffic_id'] = df_http['request_headers'].apply(
            lambda x: x.get('x_traffic_id', None) if isinstance(x, dict) else None
        )
        # conn.log と結合してuidとサービス情報を取得
        merged_http = pd.merge(df_http, df_conn[['uid', 'service']], on='uid', how='left')
        for _, row in merged_http.dropna(subset=['traffic_id']).iterrows():
            results.append({
                'traffic_id': row['traffic_id'],
                'dpi_tool': 'Zeek',
                'source_ip': row['id.orig_h'],
                'destination_ip': row['id.resp_h'],
                'zeek_detected_protocol': 'HTTP', # 強制的にHTTPとする
                'zeek_service_field': row.get('service', 'N/A') # conn.logのserviceフィールド
            })

    # DNSログからの抽出
    if not df_dns.empty:
        df_dns['traffic_id'] = df_dns['query'].apply(
            lambda x: re.search(r'test-([0-9a-f]{32})\.example\.com', x).group(1) if re.search(r'test-([0-9a-f]{32})\.example\.com', x) else None
        )
        # conn.log と結合
        merged_dns = pd.merge(df_dns, df_conn[['uid', 'service']], on='uid', how='left')
        for _, row in merged_dns.dropna(subset=['traffic_id']).iterrows():
            results.append({
                'traffic_id': row['traffic_id'],
                'dpi_tool': 'Zeek',
                'source_ip': row['id.orig_h'],
                'destination_ip': row['id.resp_h'],
                'zeek_detected_protocol': 'DNS', # 強制的にDNSとする
                'zeek_service_field': row.get('service', 'N/A') # conn.logのserviceフィールド
            })

    # カスタムICMPログからの抽出
    if not df_icmp_custom.empty:
        # カスタムICMPログはすでにtraffic_idフィールドを持っていることを期待
        for _, row in df_icmp_custom.dropna(subset=['traffic_id']).iterrows():
            results.append({
                'traffic_id': row['traffic_id'],
                'dpi_tool': 'Zeek',
                'source_ip': row['orig_h'],
                'destination_ip': row['resp_h'],
                'zeek_detected_protocol': 'ICMP', # 強制的にICMPとする
                'zeek_service_field': 'icmp' # ICMPサービスは通常固定
            })

    # SSLログはHTTPと結合して使われるため、ここでは直接のパケットID抽出はしない
    # もしSSL単独で識別したい特殊なケースがあればここに追加

    return pd.DataFrame(results)

if __name__ == "__main__":
    zeek_results_df = extract_packet_id_from_zeek()
    if not zeek_results_df.empty:
        output_file = "zeek_parsed_results.csv"
        zeek_results_df.to_csv(output_file, index=False)
        print(f"Zeek parsing complete. Results saved to {output_file}")
    else:
        print("No Zeek results to save.")