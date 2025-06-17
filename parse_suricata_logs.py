# parse_suricata_logs.py
import pandas as pd
import json
import re
import os

# Suricata eve.jsonのパス設定 (環境に合わせて要修正)
# 例: /var/log/suricata/eve.json
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

def extract_packet_id_from_suricata():
    """
    Suricataのeve.jsonからパケットIDとSuricataのプロトコル識別結果を抽出する。
    """
    if not os.path.exists(SURICATA_LOG_PATH):
        print(f"Warning: Suricata log file not found: {SURICATA_LOG_PATH}")
        return pd.DataFrame()
    
    records = []
    with open(SURICATA_LOG_PATH, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                traffic_id = None
                detected_protocol = 'UNKNOWN'
                
                # HTTPイベントからの抽出
                if event.get('event_type') == 'http':
                    # suricata.yamlでcustomヘッダー設定済みの場合
                    if 'http' in event and 'custom' in event['http'] and 'x_traffic_id' in event['http']['custom']:
                        traffic_id = event['http']['custom']['x_traffic_id']
                    elif 'http' in event and 'url' in event['http']: # URLパラメータからも抽出
                        match = re.search(r'id=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})', event['http']['url'])
                        if match:
                            traffic_id = match.group(1)
                    detected_protocol = 'HTTP'
                
                # DNSイベントからの抽出
                elif event.get('event_type') == 'dns':
                    if 'dns' in event and 'rrname' in event['dns']:
                        match = re.search(r'test-([0-9a-fA-F]{32})\.example\.com', event['dns']['rrname'])
                        if match:
                            traffic_id = match.group(1)
                    detected_protocol = 'DNS'

                # TLSイベントからの抽出 (HTTPSの識別)
                elif event.get('event_type') == 'tls':
                    # TLSイベント自体にIDは含まれないが、HTTPS通信の識別として記録
                    # IDはHTTPイベントから抽出されることを前提とする
                    detected_protocol = 'TLS'

                # アラートイベントからの抽出 (特にカスタムICMPルールなど)
                elif event.get('event_type') == 'alert':
                    if 'alert' in event and 'metadata' in event['alert'] and 'traffic_id' in event['alert']['metadata']:
                        traffic_id = event['alert']['metadata']['traffic_id']
                        detected_protocol = event['alert'].get('signature', 'Alert') # シグネチャ名をプロトコルとする
                    elif 'alert' in event and 'signature' in event['alert'] and "ICMP" in event['alert']['signature']:
                        # ICMPペイロードから直接IDを抽出するルールが設定されていない場合
                        # ここではICMPであることを識別するのみ
                        detected_protocol = 'ICMP_Alert'
                
                if traffic_id:
                    records.append({
                        'traffic_id': traffic_id,
                        'dpi_tool': 'Suricata',
                        'source_ip': event.get('src_ip'),
                        'destination_ip': event.get('dest_ip'),
                        'suricata_detected_protocol': detected_protocol,
                        'suricata_event_type': event.get('event_type')
                    })
            except json.JSONDecodeError:
                print(f"Skipping malformed JSON line in {SURICATA_LOG_PATH}: {line.strip()}")
                continue
            except Exception as e:
                print(f"Error processing event in {SURICATA_LOG_PATH}: {e} - {line.strip()}")
                continue
    return pd.DataFrame(records)

if __name__ == "__main__":
    suricata_results_df = extract_packet_id_from_suricata()
    if not suricata_results_df.empty:
        output_file = "suricata_parsed_results.csv"
        suricata_results_df.to_csv(output_file, index=False)
        print(f"Suricata parsing complete. Results saved to {output_file}")
    else:
        print("No Suricata results to save.")