# analyze_dpi_results.py
import pandas as pd
import os

# 入力ファイル名
TX_LOG_FILE = "tx_traffic_log.csv"
ZEEK_PARSED_FILE = "zeek_parsed_results.csv"
SURICATA_PARSED_FILE = "suricata_parsed_results.csv"
OUTPUT_REPORT_FILE = "dpi_evaluation_report.txt"

def load_data():
    """必要なログファイルを読み込む"""
    tx_df = pd.read_csv(TX_LOG_FILE)
    zeek_df = pd.read_csv(ZEEK_PARSED_FILE)
    suricata_df = pd.read_csv(SURICATA_PARSED_FILE)
    return tx_df, zeek_df, suricata_df

def analyze_zeek(tx_df, zeek_df):
    """Zeekの識別結果を分析する"""
    print("\n--- Analyzing Zeek Results ---")
    
    # 評価用のDataFrameを準備
    zeek_analysis_df = pd.merge(
        tx_df, 
        zeek_df[['traffic_id', 'zeek_detected_protocol', 'zeek_service_field']], 
        on='traffic_id', 
        how='left'
    )
    
    # 未検知の処理
    zeek_analysis_df['zeek_detected_protocol'].fillna('NOT_DETECTED', inplace=True)
    zeek_analysis_df['zeek_service_field'].fillna('NOT_DETECTED', inplace=True)

    # Zeekの「正解」と「DPI結果」を比較
    # ここでは'expected_protocol'と'zeek_detected_protocol'または'zeek_service_field'を比較します。
    # どのような条件で「正解」とするかは、検証の目的によって調整が必要です。
    # 例えば、VPN_VIRTUAL_NICからのHTTPS通信がZeekで'SSL'と識別された場合、それは「正解」と見なすか？
    # 'expected_protocol'にはHTTP, HTTPS(TLS), DNS, ICMPが入ることを想定
    
    # シンプルなマッチングロジックの例 (詳細な調整が必要)
    def check_zeek_match(row):
        expected = row['expected_protocol'].lower()
        detected_proto = row['zeek_detected_protocol'].lower()
        detected_service = row['zeek_service_field'].lower()

        # Zeekが特定プロトコルとして検出した場合
        if expected == 'http' and detected_proto == 'http': return 'MATCH'
        if expected == 'tls' and detected_proto == 'https': return 'MATCH' # HTTPS -> TLS
        if expected == 'tls' and detected_service == 'ssl': return 'MATCH' # HTTPS -> SSL service
        if expected == 'dns' and detected_proto == 'dns': return 'MATCH'
        if expected == 'icmp' and detected_proto == 'icmp': return 'MATCH'

        # VPN over X の検知に関するロジック
        # send_nicがVPN_VIRTUAL_NICで、ZeekがUNSPECIFIED/UNKNOWNなどと識別した場合も考慮
        # 例: VPN経由のHTTPが「HTTP」と識別されたら誤検知
        if row['send_nic'] == 'vpn_vpn01': # VPN経由の場合
            if detected_proto != 'not_detected' and detected_proto not in ['unknown', 'unspecified']: # 何らかのプロトコルとして識別された場合
                 # ここに「VPNと判断されたらMATCH」のロジックを追加
                 # 例: if detected_service == 'softether_vpn_service': return 'MATCH_VPN_DETECTED'
                 # それ以外は「誤って元のプロトコルとして検出」か「未知」
                 pass # ここは手動分析で詳細を追う

        if detected_proto == 'not_detected': return 'NOT_DETECTED'
        return 'MISMATCH' # その他の場合は不一致

    zeek_analysis_df['zeek_match_status'] = zeek_analysis_df.apply(check_zeek_match, axis=1)

    # 結果の集計
    total_traffic = len(zeek_analysis_df)
    match_count = zeek_analysis_df[zeek_analysis_df['zeek_match_status'] == 'MATCH'].shape[0]
    not_detected_count = zeek_analysis_df[zeek_analysis_df['zeek_match_status'] == 'NOT_DETECTED'].shape[0]
    mismatch_count = zeek_analysis_df[zeek_analysis_df['zeek_match_status'] == 'MISMATCH'].shape[0]

    match_rate = (match_count / total_traffic) * 100 if total_traffic > 0 else 0

    print(f"Total traffic records: {total_traffic}")
    print(f"Zeek Matched: {match_count} ({match_rate:.2f}%)")
    print(f"Zeek Not Detected: {not_detected_count}")
    print(f"Zeek Mismatched/Incorrectly Identified: {mismatch_count}")
    
    # 詳細な内訳表示
    print("\n--- Zeek Detailed Breakdown ---")
    print(zeek_analysis_df.groupby(['send_nic', 'expected_protocol', 'zeek_match_status']).size().unstack(fill_value=0))
    
    return zeek_analysis_df


def analyze_suricata(tx_df, suricata_df):
    """Suricataの識別結果を分析する"""
    print("\n--- Analyzing Suricata Results ---")
    
    # 評価用のDataFrameを準備
    suricata_analysis_df = pd.merge(
        tx_df, 
        suricata_df[['traffic_id', 'suricata_detected_protocol', 'suricata_event_type']], 
        on='traffic_id', 
        how='left'
    )

    # 未検知の処理
    suricata_analysis_df['suricata_detected_protocol'].fillna('NOT_DETECTED', inplace=True)
    suricata_analysis_df['suricata_event_type'].fillna('NOT_DETECTED', inplace=True)

    # Suricataの「正解」と「DPI結果」を比較
    def check_suricata_match(row):
        expected = row['expected_protocol'].lower()
        detected_proto = row['suricata_detected_protocol'].lower()
        event_type = row['suricata_event_type'].lower()

        # Suricataが特定プロトコルとして検出した場合
        if expected == 'http' and detected_proto == 'http': return 'MATCH'
        if expected == 'tls' and detected_proto == 'tls': return 'MATCH'
        if expected == 'dns' and detected_proto == 'dns': return 'MATCH'
        
        # ICMPはカスタムアラートでの検知を期待
        if expected == 'icmp' and 'icmp' in detected_proto and event_type == 'alert': return 'MATCH_ALERTED_ICMP'

        # VPN over X の検知に関するロジック
        if row['send_nic'] == 'vpn_vpn01': # VPN経由の場合
            if 'vpn' in detected_proto or 'softether' in detected_proto: # カスタムルールでVPNと識別された場合
                 return 'MATCH_VPN_DETECTED'
            elif event_type == 'alert': # なんらかのアラートが発生した場合も考慮
                 return 'MATCH_ALERT_FOR_VPN_TRAFFIC'
            # else: 誤って元のプロトコルとして検出されたり、NOT_DETECTEDの場合

        if detected_proto == 'not_detected': return 'NOT_DETECTED'
        return 'MISMATCH'

    suricata_analysis_df['suricata_match_status'] = suricata_analysis_df.apply(check_suricata_match, axis=1)

    # 結果の集計
    total_traffic = len(suricata_analysis_df)
    match_count = suricata_analysis_df[suricata_analysis_df['suricata_match_status'].str.startswith('MATCH')].shape[0]
    not_detected_count = suricata_analysis_df[suricata_analysis_df['suricata_match_status'] == 'NOT_DETECTED'].shape[0]
    mismatch_count = suricata_analysis_df[suricata_analysis_df['suricata_match_status'] == 'MISMATCH'].shape[0]

    match_rate = (match_count / total_traffic) * 100 if total_traffic > 0 else 0

    print(f"Total traffic records: {total_traffic}")
    print(f"Suricata Matched (including VPN alerts): {match_count} ({match_rate:.2f}%)")
    print(f"Suricata Not Detected: {not_detected_count}")
    print(f"Suricata Mismatched/Incorrectly Identified: {mismatch_count}")
    
    # 詳細な内訳表示
    print("\n--- Suricata Detailed Breakdown ---")
    print(suricata_analysis_df.groupby(['send_nic', 'expected_protocol', 'suricata_match_status']).size().unstack(fill_value=0))

    return suricata_analysis_df

def main():
    tx_df, zeek_df, suricata_df = load_data()

    if tx_df.empty:
        print(f"Error: TX log file '{TX_LOG_FILE}' not found or empty. Please run traffic_generator.py first.")
        return
    
    # Zeek解析を実行
    zeek_final_df = analyze_zeek(tx_df.copy(), zeek_df.copy()) # copy()でDataFrameが変更されないように
    
    # Suricata解析を実行
    suricata_final_df = analyze_suricata(tx_df.copy(), suricata_df.copy())

    # レポートの書き出し (必要に応じて追加情報を出力)
    with open(OUTPUT_REPORT_FILE, 'w') as f:
        f.write("DPI Evaluation Report\n")
        f.write("=======================\n")
        
        f.write("\n--- Zeek Summary ---\n")
        f.write(f"Total traffic records: {len(zeek_final_df)}\n")
        f.write(f"Zeek Matched: {zeek_final_df[zeek_final_df['zeek_match_status'] == 'MATCH'].shape[0]} ({(zeek_final_df[zeek_final_df['zeek_match_status'] == 'MATCH'].shape[0] / len(zeek_final_df)) * 100:.2f}%)\n")
        f.write(f"Zeek Not Detected: {zeek_final_df[zeek_final_df['zeek_match_status'] == 'NOT_DETECTED'].shape[0]}\n")
        f.write(f"Zeek Mismatched/Incorrectly Identified: {zeek_final_df[zeek_final_df['zeek_match_status'] == 'MISMATCH'].shape[0]}\n")
        f.write("\nDetailed Breakdown:\n")
        f.write(zeek_final_df.groupby(['send_nic', 'expected_protocol', 'zeek_match_status']).size().unstack(fill_value=0).to_string() + "\n")
        
        f.write("\n--- Suricata Summary ---\n")
        f.write(f"Total traffic records: {len(suricata_final_df)}\n")
        f.write(f"Suricata Matched (including VPN alerts): {suricata_final_df[suricata_final_df['suricata_match_status'].str.startswith('MATCH')].shape[0]} ({(suricata_final_df[suricata_final_df['suricata_match_status'].str.startswith('MATCH')].shape[0] / len(suricata_final_df)) * 100:.2f}%)\n")
        f.write(f"Suricata Not Detected: {suricata_final_df[suricata_final_df['suricata_match_status'] == 'NOT_DETECTED'].shape[0]}\n")
        f.write(f"Suricata Mismatched/Incorrectly Identified: {suricata_final_df[suricata_final_df['suricata_match_status'] == 'MISMATCH'].shape[0]}\n")
        f.write("\nDetailed Breakdown:\n")
        f.write(suricata_final_df.groupby(['send_nic', 'expected_protocol', 'suricata_match_status']).size().unstack(fill_value=0).to_string() + "\n")

    print(f"\nDPI evaluation complete. Report saved to {OUTPUT_REPORT_FILE}")

if __name__ == "__main__":
    main()