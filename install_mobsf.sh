#!/bin/bash

# MobSF 部署脚本
set -e

echo "开始安装 Mobile Security Framework (MobSF)..."

# 设置环境变量
export DEBIAN_FRONTEND=noninteractive
export LANG=zh_CN.UTF-8
export LANGUAGE=zh_CN:zh
export LC_ALL=zh_CN.UTF-8
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONFAULTHANDLER=1
export MOBSF_USER=mobsf
export USER_ID=9901
export MOBSF_PLATFORM=local
export MOBSF_ADB_BINARY=/usr/bin/adb
export JAVA_HOME=/jdk-22.0.2
export PATH=/jdk-22.0.2/bin:$HOME/.local/bin:$PATH
export DJANGO_SUPERUSER_USERNAME=mobsf
export DJANGO_SUPERUSER_PASSWORD=mobsf

# 安装系统依赖
# echo "安装系统依赖..."
# sudo apt update -y
# sudo apt install -y --no-install-recommends \
#     android-sdk-build-tools \
#     android-tools-adb \
#     build-essential \
#     curl \
#     fontconfig \
#     fontconfig-config \
#     git \
#     libfontconfig1 \
#     libxext6 \
#     libxrender1 \
#     locales \
#     python3-dev \
#     sqlite3 \
#     unzip \
#     wget \
#     xfonts-75dpi \
#     xfonts-base

# # 设置中文语言环境
# echo "设置中文语言环境..."
# sudo bash -c 'echo "zh_CN.UTF-8 UTF-8" > /etc/locale.gen'
# sudo locale-gen zh_CN.UTF-8
# sudo update-locale LANG=zh_CN.UTF-8

# # 升级系统
# sudo apt upgrade -y

# # 安装 Poetry
# echo "安装 Poetry..."
# curl -sSL https://install.python-poetry.org | python3 -

# # 清理不必要的包
# sudo apt autoremove -y && sudo apt clean -y

# 创建工作目录
WORK_DIR="/usr/local/863/bin/Mobile-Security-Framework-MobSF"
mkdir -p $WORK_DIR
cd $WORK_DIR

# # 克隆 MobSF 仓库
# echo "克隆 MobSF 仓库..."
# git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git .

# 运行依赖安装脚本
echo "安装 wkhtmltopdf, OpenJDK 和 jadx..."
bash ./scripts/dependencies.sh

# 安装 Python 依赖
echo "安装 Python 依赖..."
poetry config virtualenvs.create false
poetry lock
poetry install --only main --no-root --no-interaction --no-ansi
poetry cache clear . --all --no-interaction

# # 清理
# echo "清理系统..."
# sudo apt remove -y \
#     git \
#     python3-dev \
#     wget
# sudo apt clean
# sudo apt autoclean
# sudo apt autoremove -y

# 创建 mobsf 用户
echo "创建 mobsf 用户..."
sudo groupadd --gid $USER_ID $MOBSF_USER || true
sudo useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --shell /bin/false --create-home || true
sudo chown -R $MOBSF_USER:$MOBSF_USER $WORK_DIR

# 创建启动脚本
cat > $WORK_DIR/start_mobsf.sh << 'EOF'
#!/bin/bash
cd $HOME/Mobile-Security-Framework-MobSF
python3 manage.py runserver 0.0.0.0:8000
EOF

chmod +x $WORK_DIR/start_mobsf.sh
sudo chown $MOBSF_USER:$MOBSF_USER $WORK_DIR/start_mobsf.sh

# 创建服务文件
cat > /tmp/mobsf.service << 'EOF'
[Unit]
Description=Mobile Security Framework Service
After=network.target

[Service]
Type=simple
User=mobsf
WorkingDirectory=/home/mobsf/Mobile-Security-Framework-MobSF
ExecStart=/home/mobsf/Mobile-Security-Framework-MobSF/start_mobsf.sh
Restart=on-failure
# 添加环境变量
Environment="PYTHONUNBUFFERED=1"
Environment="PYTHONDONTWRITEBYTECODE=1"
Environment="PYTHONFAULTHANDLER=1"
Environment="MOBSF_PLATFORM=local"
Environment="MOBSF_ADB_BINARY=/usr/bin/adb"
Environment="JAVA_HOME=/jdk-22.0.2"
Environment="PATH=/jdk-22.0.2/bin:/home/mobsf/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="DJANGO_SUPERUSER_USERNAME=mobsf"
Environment="DJANGO_SUPERUSER_PASSWORD=mobsf"
Environment="LANG=zh_CN.UTF-8"
Environment="LANGUAGE=zh_CN:zh"
Environment="LC_ALL=zh_CN.UTF-8"

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/mobsf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable mobsf.service


echo "MobSF 安装完成！"
echo "您可以通过以下命令启动服务："
echo "sudo systemctl start mobsf"
echo "然后访问 http://localhost:8000 使用 MobSF"
echo "默认用户名: mobsf"
echo "默认密码: mobsf"