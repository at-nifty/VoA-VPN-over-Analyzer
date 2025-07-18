# estimate_detection_patterns.py

# このファイルは、Zeek および Suricata における SoftEther VPN (特に VPN over DNS/ICMP) の
# 検知パターンを推定し、カスタムルールやスクリプトを作成するためのガイドラインです。
# コードを実行するものではなく、分析と検討のプロセスを記録するためのものです。

# --- 目的 ---
# 1. SoftEther VPN の VPN over DNS/ICMP トラフィックを詳細に分析し、DPI 回避の仕組みを理解する。
# 2. DPI ツール (Zeek/Suricata) がこのトラフィックをどのように識別・検知するかを検証する。
# 3. 未検知の場合、検知を可能にするための具体的なシグネチャ、行動パターン、ヒューリスティックを特定する。
# 4. 特定したパターンに基づき、Zeek スクリプトおよび Suricata ルールを作成・改善する。

# --- フェーズ 1: Wireshark による詳細なパケット分析 ---
# `traffic_generator.py` を実行し、MX VM の `ens19` (物理NIC) および `ens20` (仮想NIC) で
# Wireshark を使ってパケットをキャプチャする。

# 1. VPN over DNS/ICMP トラフィック (ens19 側)
#    - TCP/UDP 53 (DNS) または ICMP のフィルターを適用。
#    - 各パケットの詳細 (プロトコルヘッダ、ペイロードのバイナリデータ) を確認。
#    - SoftEther VPN のプロトコル仕様 (もし公開されていれば) と照らし合わせる。
#    - **探すべきパターンと特徴:**
#        - **Magic Number / 固定バイト列:** プロトコル開始時やセッション中に現れる特徴的なバイト列。
#          例: 特定のオフセットに `0x1A 0x2B 0x3C 0x4D` のようなシーケンスが存在するか？
#        - **固定値フィールド:** 特定のヘッダフィールドが常に同じ値を取るか？ (例: プロトコルバージョン、フラグの一部)
#        - **パケット長の均一性 / 異常性:** 暗号化後のペイロードサイズが不自然に固定されているか？
#          通常の DNS/ICMP パケットとは異なる長さのパターンが見られるか？
#        - **ハンドシェイクパターン:** セッション確立時の特定のコマンドシーケンスやデータのやり取り。
#        - **タイムスタンプ / シーケンス番号のパターン:** 暗号化されていても、これらの値の変動に規則性がないか？
#        - **データの「エントロピー」:** ペイロードが通常の DNS/ICMP データ