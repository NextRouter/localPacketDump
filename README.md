# Local Packet Dump

ネットワークパケットをキャプチャして、IP アドレス別の通信統計をリアルタイムで監視するツールです。Prometheus メトリクスとして出力し、Web インターフェースで確認できます。

## 🚀 クイックスタート

### ワンコマンドで実行

```bash
curl -sSL https://raw.githubusercontent.com/NextRouter/localPacketDump/main/install.sh | bash
```

### 手動インストール

```bash
# リポジトリをクローン
git clone https://github.com/NextRouter/localPacketDump.git
cd localPacketDump

# 一回だけ実行
./run.sh

# または systemdサービスとして登録
./setup-systemd.sh
```

## 📋 必要要件

- Linux OS
- Rust 1.70+
- sudo 権限（パケットキャプチャのため）
- libpcap 開発ライブラリ

## 🔧 機能

- **リアルタイムパケット監視**: ネットワークインターフェースからパケットをキャプチャ
- **IP 別統計**: 送受信バイト数、bps、再送信数などを IP 別に集計
- **Prometheus メトリクス**: `http://localhost:9090/metrics` でメトリクス取得
- **自動ネットワークインターフェース検出**: アクティブなインターフェースを自動選択

## 📊 提供メトリクス

- `network_ip_tx_bytes_total`: IP 別送信バイト総数
- `network_ip_rx_bytes_total`: IP 別受信バイト総数
- `network_ip_tx_bytes_per_sec`: IP 別送信バイト/秒
- `network_ip_rx_bytes_per_sec`: IP 別受信バイト/秒
- `network_ip_tx_bps`: IP 別送信ビット/秒
- `network_ip_rx_bps`: IP 別受信ビット/秒
- `network_ip_retransmissions_per_sec`: IP 別再送信/秒
- `network_ip_duplicate_acks_per_sec`: IP 別重複 ACK/秒

## 🛠️ 手動ビルド

```bash
# 依存関係インストール (Ubuntu/Debian)
sudo apt update
sudo apt install -y libpcap-dev build-essential

# Rustインストール (未インストールの場合)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# ビルド & 実行
cargo build --release
sudo ./target/release/localpacketDump
```

## 🌐 メトリクス確認

プログラム実行中に以下でメトリクスを確認：

```bash
curl http://localhost:9090/metrics
```

## 🔧 systemd サービスとして登録

### 1. サービスファイル作成

```bash
sudo tee /etc/systemd/system/localpacketdump.service > /dev/null <<EOF
[Unit]
Description=Local Packet Dump Network Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$(pwd)/target/release/localpacketDump
WorkingDirectory=$(pwd)
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# セキュリティ設定
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF
```

### 2. サービス有効化・開始

```bash
# systemd設定リロード
sudo systemctl daemon-reload

# サービス有効化（起動時自動開始）
sudo systemctl enable localpacketdump.service

# サービス開始
sudo systemctl start localpacketdump.service
```

### 3. サービス管理コマンド

```bash
# ステータス確認
sudo systemctl status localpacketdump.service

# ログ確認
sudo journalctl -u localpacketdump.service -f

# サービス停止
sudo systemctl stop localpacketdump.service

# サービス再起動
sudo systemctl restart localpacketdump.service

# 自動起動無効化
sudo systemctl disable localpacketdump.service

# サービス削除
sudo systemctl stop localpacketdump.service
sudo systemctl disable localpacketdump.service
sudo rm /etc/systemd/system/localpacketdump.service
sudo systemctl daemon-reload
```

### 4. 自動セットアップスクリプト

systemd サービスの自動登録：

```bash
./setup-systemd.sh
```

## ⚠️ 注意事項

- パケットキャプチャには root 権限が必要です
- ファイアウォールでポート 9090 が開いていることを確認してください
- 大量トラフィック環境では CPU 使用率が高くなる可能性があります

## 📝 ライセンス

MIT License
