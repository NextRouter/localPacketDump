#!/bin/bash

# Local Packet Dump - 簡単実行スクリプト
set -e

echo "🚀 Local Packet Dump セットアップを開始します..."

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# OS検出
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "ubuntu"
        elif command -v yum >/dev/null 2>&1; then
            echo "rhel"
        else
            echo "linux"
        fi
    else
        echo "unsupported"
    fi
}

# 依存関係インストール
install_dependencies() {
    local os=$(detect_os)
    
    case $os in
        "ubuntu")
            echo -e "${YELLOW}📦 依存関係をインストール中...${NC}"
            sudo apt update
            sudo apt install -y libpcap-dev build-essential curl
            ;;
        "rhel")
            echo -e "${YELLOW}📦 依存関係をインストール中...${NC}"
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y libpcap-devel curl
            ;;
        *)
            echo -e "${RED}❌ サポートされていないOSです。手動で libpcap-dev をインストールしてください。${NC}"
            ;;
    esac
}

# Rustインストール確認
check_rust() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${YELLOW}🦀 Rustをインストール中...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo -e "${GREEN}✅ Rustが既にインストールされています${NC}"
    fi
}

# root権限確認
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

# ビルド
build_project() {
    echo -e "${YELLOW}🔨 プロジェクトをビルド中...${NC}"
    cargo build --release
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ ビルド完了${NC}"
    else
        echo -e "${RED}❌ ビルドに失敗しました${NC}"
        exit 1
    fi
}

# 実行
run_application() {
    echo -e "${GREEN}🎯 Local Packet Dumpを起動中...${NC}"
    echo -e "${YELLOW}📊 メトリクスは http://localhost:9090/metrics で確認できます${NC}"
    echo -e "${YELLOW}⏹️  停止するには Ctrl+C を押してください${NC}"
    echo ""
    
    if [ "$EUID" -eq 0 ]; then
        ./target/release/localpacketDump
    else
        sudo ./target/release/localpacketDump
    fi
}

# メイン実行
main() {
    echo -e "${GREEN}🌟 Local Packet Dump 自動セットアップ${NC}"
    echo "=================================="
    
    # 依存関係チェック・インストール
    install_dependencies
    
    # Rust環境チェック
    check_rust
    
    # sudo権限チェック
    check_sudo
    
    # ビルド
    build_project
    
    # 実行
    echo ""
    echo -e "${GREEN}🎉 セットアップ完了！アプリケーションを起動します...${NC}"
    echo ""
    
    run_application
}

# スクリプト実行
main "$@"
