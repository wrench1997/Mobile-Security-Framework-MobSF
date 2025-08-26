#!/bin/bash

# MobSF 部署脚本
set -e

echo "开始安装 Mobile Security Framework (MobSF)..."



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
WORK_DIR="/usr/local/863/Mobile-Security-Framework-MobSF"
rm -rf $WORK_DIR
mkdir -p $WORK_DIR
mkdir -p $WORK_DIR/.MOBSF

# 拷贝必要文件到工作目录
echo "拷贝必要文件到工作目录..."
cp -r mobsf $WORK_DIR/
cp -r scripts $WORK_DIR/
cp -r tools_bin $WORK_DIR/
cp install_mobsf.sh $WORK_DIR/
cp manage.py $WORK_DIR/
cp poetry.lock $WORK_DIR/
cp pyproject.toml $WORK_DIR/
cp README.md $WORK_DIR/

# 切换到工作目录
cd $WORK_DIR

# # 克隆 MobSF 仓库
# echo "克隆 MobSF 仓库..."
# git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git .

# 运行依赖安装脚本
echo "安装 wkhtmltopdf, OpenJDK 和 jadx..."
bash scripts/dependencies.sh

# 安装 Python 依赖
echo "安装 Python 依赖..."
poetry config virtualenvs.create true
poetry install

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
# echo "创建 mobsf 用户..."
# sudo groupadd --gid $USER_ID $MOBSF_USER || true
# sudo useradd $MOBSF_USER --uid $USER_ID --gid $MOBSF_USER --shell /bin/false --create-home || true
# sudo chown -R $MOBSF_USER:$MOBSF_USER $WORK_DIR


# export MOBSF_SECRET_KEY=0d)rnfj(f1(sc)4g-k**p)vxad6$*par!=)5urn*0xk9m)=4ns 这个在源代码里面固定死了，所以改不改变量一样
# 创建启动脚本
cat > $WORK_DIR/start_mobsf.sh << 'EOF'
#!/bin/bash
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
export JAVA_HOME=/usr/local/863/Mobile-Security-Framework-MobSF/jdk-22.0.2
export PATH=/usr/local/863/Mobile-Security-Framework-MobSF/jdk-22.0.2/bin:/home/mobsf/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/root/.local/bin:/usr/bin:/sbin:/bin
export DJANGO_SUPERUSER_USERNAME=mobsf
export DJANGO_SUPERUSER_PASSWORD=mobsf
export MOBSF_JADX_BINARY=/usr/local/863/Mobile-Security-Framework-MobSF/.MOBSF/tools/jadx/jadx-1.5.0/bin/jadx
export MOBSF_HOME_DIR=/usr/local/863/Mobile-Security-Framework-MobSF/.MOBSF
export MOBSF_API_KEY=4154386320cab110d7b8bf4d5475b3cde8833fea0045cb1768c11ddee838395a

source $(poetry env info --path)/bin/activate && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate
set +e
python3 manage.py createsuperuser --noinput --email ""
set -e
python3 manage.py create_roles

exec gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600 \
    --worker-tmp-dir=/dev/shm --log-level=citical --log-file=- --access-logfile=- --error-logfile=- --capture-output
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
User=root
PermissionsStartOnly=true
WorkingDirectory=/usr/local/863/Mobile-Security-Framework-MobSF
ExecStart=/usr/local/863/Mobile-Security-Framework-MobSF/start_mobsf.sh
Restart=on-failure
RestartSec=10s
TimeoutStartSec=300
# 添加环境变量
Environment="PYTHONUNBUFFERED=1"
Environment="PYTHONDONTWRITEBYTECODE=1"
Environment="PYTHONFAULTHANDLER=1"
Environment="MOBSF_PLATFORM=local"
Environment="MOBSF_ADB_BINARY=/usr/bin/adb"
Environment="JAVA_HOME=/usr/local/863/Mobile-Security-Framework-MobSF/jdk-22.0.2"
Environment="PATH=/usr/local/863/Mobile-Security-Framework-MobSF/jdk-22.0.2/bin:/home/mobsf/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/root/.local/bin:/usr/bin:/sbin:/bin:/usr/local/863/Mobile-Security-Framework-MobSF/.MOBSF/tools/jadx/jadx-1.5.0/bin"
Environment="DJANGO_SUPERUSER_USERNAME=mobsf"
Environment="DJANGO_SUPERUSER_PASSWORD=mobsf"
Environment="LANG=zh_CN.UTF-8"
Environment="LANGUAGE=zh_CN:zh"
Environment="LC_ALL=zh_CN.UTF-8"
Environment="MOBSF_HOME_DIR=/usr/local/863/Mobile-Security-Framework-MobSF/.MOBSF"

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/mobsf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable mobsf.service
sudo systemctl restart mobsf.service


echo "MobSF 安装完成！"
echo "您可以通过以下命令启动服务："
echo "sudo systemctl start mobsf"
echo "然后访问 http://localhost:8000 使用 MobSF"
echo "默认用户名: mobsf"
echo "默认密码: mobsf"