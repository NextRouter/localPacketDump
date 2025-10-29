 #!/bin/bash

# Local Packet Dump - systemdサービス自動セットアップスクリプト
set -e

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 設定
SERVICE_NAME="localpacketdump"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CURRENT_DIR=$(pwd)
BINARY_PATH="${CURRENT_DIR}/target/release/localpacketDump"

echo -e "${BLUE}🔧 Local Packet Dump systemdサービス セットアップ${NC}"
echo "================================================="

# root権限チェック
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "${GREEN}✅ root権限で実行中${NC}"
        return 0
    fi
    
    if sudo -n true 2>/dev/null; then
        echo -e "${GREEN}✅ sudo権限が利用可能${NC}"
        return 0
    else
        echo -e "${RED}❌ sudo権限が必要です。パスワードを入力してください：${NC}"
        sudo true
    fi
}

# バイナリ存在チェック
check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${RED}❌ バイナリが見つかりません: $BINARY_PATH${NC}"
        echo -e "${YELLOW}💡 まず './run.sh' でビルドを実行してください${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ バイナリを確認: $BINARY_PATH${NC}"
    fi
}

# 既存サービス確認
check_existing_service() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  サービスが既に実行中です${NC}"
        read -p "サービスを停止して再設定しますか？ (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}🔄 既存サービスを停止中...${NC}"
            sudo systemctl stop "$SERVICE_NAME"
        else
            echo -e "${BLUE}ℹ️  既存サービスをそのまま使用します${NC}"
            exit 0
        fi
    fi
}

# サービスファイル作成
create_service_file() {
    echo -e "${YELLOW}📝 サービスファイルを作成中: $SERVICE_FILE${NC}"
    
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Local Packet Dump Network Monitor
Documentation=https://github.com/NextRouter/localPacketDump
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$BINARY_PATH eth2
WorkingDirectory=$CURRENT_DIR
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=localpacketdump

# セキュリティ設定
NoNewPrivileges=true
ProtectSystem=strict
# ProtectHome=true
ReadWritePaths=/tmp
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# リソース制限
LimitNOFILE=65536
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}✅ サービスファイル作成完了${NC}"
}

# systemd設定
setup_systemd() {
    echo -e "${YELLOW}🔄 systemd設定を更新中...${NC}"
    sudo systemctl daemon-reload
    
    echo -e "${YELLOW}🚀 サービスを有効化中...${NC}"
    sudo systemctl enable "$SERVICE_NAME"
    
    echo -e "${YELLOW}▶️  サービスを開始中...${NC}"
    sudo systemctl start "$SERVICE_NAME"
    
    # 少し待ってからステータス確認
    sleep 2
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${GREEN}✅ サービスが正常に開始されました${NC}"
    else
        echo -e "${RED}❌ サービスの開始に失敗しました${NC}"
        echo -e "${YELLOW}📋 ログを確認してください:${NC}"
        sudo journalctl -u "$SERVICE_NAME" --no-pager -n 10
        exit 1
    fi
}

# ステータス表示
show_status() {
    echo ""
    echo -e "${BLUE}📊 サービス情報${NC}"
    echo "===================="
    echo -e "${YELLOW}サービス名:${NC} $SERVICE_NAME"
    echo -e "${YELLOW}設定ファイル:${NC} $SERVICE_FILE"
    echo -e "${YELLOW}バイナリパス:${NC} $BINARY_PATH"
    echo -e "${YELLOW}作業ディレクトリ:${NC} $CURRENT_DIR"
    echo ""
    
    echo -e "${BLUE}📈 サービスステータス${NC}"
    echo "====================="
    sudo systemctl status "$SERVICE_NAME" --no-pager -l
    echo ""
    
    echo -e "${GREEN}🎉 セットアップ完了！${NC}"
    echo ""
    echo -e "${BLUE}💡 使用可能なコマンド:${NC}"
    echo "  sudo systemctl status $SERVICE_NAME     # ステータス確認"
    echo "  sudo systemctl stop $SERVICE_NAME       # サービス停止"
    echo "  sudo systemctl start $SERVICE_NAME      # サービス開始"
    echo "  sudo systemctl restart $SERVICE_NAME    # サービス再起動"
    echo "  sudo journalctl -u $SERVICE_NAME -f     # ログをリアルタイム表示"
    echo "  curl http://localhost:9090/metrics       # メトリクス確認"
    echo ""
    echo -e "${YELLOW}⚠️  サービスを削除する場合:${NC}"
    echo "  sudo systemctl stop $SERVICE_NAME && sudo systemctl disable $SERVICE_NAME"
    echo "  sudo rm $SERVICE_FILE && sudo systemctl daemon-reload"
}

# アンインストール関数
uninstall_service() {
    echo -e "${YELLOW}🗑️  サービスをアンインストール中...${NC}"
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        sudo systemctl stop "$SERVICE_NAME"
        echo -e "${GREEN}✅ サービスを停止しました${NC}"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        sudo systemctl disable "$SERVICE_NAME"
        echo -e "${GREEN}✅ サービスを無効化しました${NC}"
    fi
    
    if [ -f "$SERVICE_FILE" ]; then
        sudo rm "$SERVICE_FILE"
        echo -e "${GREEN}✅ サービスファイルを削除しました${NC}"
    fi
    
    sudo systemctl daemon-reload
    echo -e "${GREEN}✅ アンインストール完了${NC}"
}

# メイン実行
main() {
    case "${1:-install}" in
        "install"|"setup")
            check_sudo
            check_binary
            check_existing_service
            create_service_file
            setup_systemd
            show_status
            ;;
        "uninstall"|"remove")
            check_sudo
            uninstall_service
            ;;
        "status")
            sudo systemctl status "$SERVICE_NAME"
            ;;
        *)
            echo "使用方法: $0 [install|uninstall|status]"
            echo "  install   - サービスをインストール・開始 (デフォルト)"
            echo "  uninstall - サービスをアンインストール"
            echo "  status    - サービスステータスを表示"
            exit 1
            ;;
    esac
}

# スクリプト実行
main "$@"
