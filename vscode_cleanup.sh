#!/bin/bash

# VSCode + Claude Code 环境变量彻底清理脚本

RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

echo -e "\n${RED}========================================${NC}"
echo -e "${RED}VSCode + Claude Code 环境变量彻底清理${NC}"
echo -e "${RED}========================================${NC}\n"

print_info "检测到您在使用 VSCode 集成终端"
print_info "当前环境变量状态："
declare -p | grep ANTHROPIC

# 1. 立即清理当前会话
print_info "\n=== 步骤1: 清理当前会话 ==="
unset ANTHROPIC_BASE_URL
unset ANTHROPIC_API_KEY  
unset ANTHROPIC_AUTH_TOKEN

print_success "当前会话变量已清理"

# 2. 找到并清理所有配置文件
print_info "\n=== 步骤2: 清理配置文件 ==="

CONFIG_FILES=(
    "/etc/environment"
    "/etc/profile"
    "/etc/bash.bashrc"
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.bash_login"
    "$HOME/.profile"
    "$HOME/.zshrc"
    "$HOME/.zshenv"
    "$HOME/.zprofile"
)

for file in "${CONFIG_FILES[@]}"; do
    if [ -f "$file" ]; then
        if grep -q "ANTHROPIC" "$file" 2>/dev/null; then
            print_warning "发现并清理: $file"
            
            # 创建备份
            backup="$file.vscode_cleanup_$(date +%Y%m%d_%H%M%S)"
            if [[ "$file" == /etc/* ]]; then
                sudo cp "$file" "$backup"
                sudo sed -i '/ANTHROPIC/d' "$file"
            else
                cp "$file" "$backup"
                sed -i '/ANTHROPIC/d' "$file"
            fi
            
            print_success "已清理: $file (备份: $backup)"
            
            # 显示被清理的内容
            echo "被清理的内容："
            grep "ANTHROPIC" "$backup" 2>/dev/null || true
            echo "---"
        fi
    fi
done

# 3. 清理 VSCode 相关配置
print_info "\n=== 步骤3: 清理 VSCode 相关配置 ==="

# VSCode 用户设置
VSCODE_SETTINGS="$HOME/.vscode-server/data/User/settings.json"
if [ -f "$VSCODE_SETTINGS" ]; then
    if grep -q "ANTHROPIC" "$VSCODE_SETTINGS" 2>/dev/null; then
        print_warning "清理 VSCode 设置: $VSCODE_SETTINGS"
        cp "$VSCODE_SETTINGS" "$VSCODE_SETTINGS.backup.$(date +%Y%m%d_%H%M%S)"
        sed -i '/ANTHROPIC/d' "$VSCODE_SETTINGS"
        print_success "已清理 VSCode 设置"
    fi
fi

# VSCode 工作区设置
if [ -f ".vscode/settings.json" ]; then
    if grep -q "ANTHROPIC" ".vscode/settings.json" 2>/dev/null; then
        print_warning "清理工作区设置: .vscode/settings.json"
        cp ".vscode/settings.json" ".vscode/settings.json.backup.$(date +%Y%m%d_%H%M%S)"
        sed -i '/ANTHROPIC/d' ".vscode/settings.json"
        print_success "已清理工作区设置"
    fi
fi

# 4. 清理 .claude.json
print_info "\n=== 步骤4: 清理 .claude.json ==="
if [ -f "$HOME/.claude.json" ]; then
    cp "$HOME/.claude.json" "$HOME/.claude.json.vscode_backup.$(date +%Y%m%d_%H%M%S)"
    echo '{"customApiKeyResponses":{"approved":[]}}' > "$HOME/.claude.json"
    print_success "已重置 ~/.claude.json"
fi

# 5. 创建强制清理脚本
print_info "\n=== 步骤5: 创建强制清理机制 ==="

# 创建清理脚本
cat > /tmp/force_claude_cleanup.sh << 'EOF'
#!/bin/bash
# 强制清理 ANTHROPIC 环境变量
unset ANTHROPIC_BASE_URL 2>/dev/null || true
unset ANTHROPIC_API_KEY 2>/dev/null || true  
unset ANTHROPIC_AUTH_TOKEN 2>/dev/null || true

# 防止重新设置
export ANTHROPIC_BASE_URL=""
export ANTHROPIC_API_KEY=""
export ANTHROPIC_AUTH_TOKEN=""
unset ANTHROPIC_BASE_URL
unset ANTHROPIC_API_KEY
unset ANTHROPIC_AUTH_TOKEN
EOF

chmod +x /tmp/force_claude_cleanup.sh

# 将强制清理添加到 .bashrc 的最开头
if [ -f "$HOME/.bashrc" ]; then
    # 移除之前可能添加的清理脚本
    sed -i '/force_claude_cleanup/d' "$HOME/.bashrc"
    sed -i '/claude_cleanup/d' "$HOME/.bashrc"
    
    # 在文件开头添加强制清理
    sed -i '1i\# Force cleanup ANTHROPIC variables\nsource /tmp/force_claude_cleanup.sh 2>/dev/null || true' "$HOME/.bashrc"
    print_success "已添加强制清理到 .bashrc"
fi

# 6. 验证清理结果
print_info "\n=== 步骤6: 验证清理结果 ==="
echo "当前环境变量："
env | grep ANTHROPIC || print_success "✓ 环境变量已清理"

echo -e "\n检查 declare 状态："
declare -p | grep ANTHROPIC || print_success "✓ declare 变量已清理"

print_success "\n清理完成！"

echo -e "\n${RED}重要：现在请按以下步骤操作：${NC}"
echo -e "${YELLOW}1. 关闭 VSCode 完全退出${NC}"
echo -e "${YELLOW}2. 关闭所有终端窗口${NC}"  
echo -e "${YELLOW}3. 重新启动 VSCode${NC}"
echo -e "${YELLOW}4. 打开新的集成终端${NC}"
echo -e "${YELLOW}5. 运行: echo \$ANTHROPIC_API_KEY${NC}"

echo -e "\n${GREEN}如果清理成功，请运行以下命令移除临时清理脚本：${NC}"
echo -e "${BLUE}sed -i '/force_claude_cleanup/d' ~/.bashrc${NC}"
echo -e "${BLUE}rm -f /tmp/force_claude_cleanup.sh${NC}"

echo -e "\n${RED}如果仍有问题，请重启整个系统！${NC}"

exit 0
