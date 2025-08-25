#!/bin/bash
JDK_FILE=openjdk-22.0.2_linux-x64_bin.tar.gz
JDK_FILE_ARM=openjdk-22.0.2_linux-aarch64_bin.tar.gz
WKH_FILE=wkhtmltox_0.12.6.1-3.bookworm_amd64.deb
WKH_FILE_ARM=wkhtmltox_0.12.6.1-3.bookworm_arm64.deb

# 创建 apktool 框架目录
mkdir -p /home/mobsf/.local/share/apktool/framework

# 根据目标平台选择正确的文件
if [ "$TARGETPLATFORM" == "linux/arm64" ]
then
    WKH_FILE=$WKH_FILE_ARM
    JDK_FILE=$JDK_FILE_ARM
fi

echo "目标平台识别为 $TARGETPLATFORM"

# 设置工具二进制文件路径
TOOLS_BIN_PATH="tools_bin"

# 安装 wkhtmltopdf (从本地文件)
echo "从本地安装 $WKH_FILE ..."
if [ -f "${TOOLS_BIN_PATH}/${WKH_FILE}" ]; then
    dpkg -i "${TOOLS_BIN_PATH}/${WKH_FILE}" && \
    apt-get install -f -y --no-install-recommends && \
    ln -s /usr/local/bin/wkhtmltopdf /usr/bin
else
    echo "错误: ${TOOLS_BIN_PATH}/${WKH_FILE} 不存在"
    exit 1
fi

# 安装 OpenJDK (从本地文件)
echo "从本地安装 $JDK_FILE ..."
if [ -f "${TOOLS_BIN_PATH}/${JDK_FILE}" ]; then
    tar zxf "${TOOLS_BIN_PATH}/${JDK_FILE}"
else
    echo "错误: ${TOOLS_BIN_PATH}/${JDK_FILE} 不存在"
    exit 1
fi

# 安装 JADX (从本地文件)
echo "从本地安装 JADX ..."
JADX_ZIP="${TOOLS_BIN_PATH}/jadx-1.5.0.zip"
JADX_DIR="/home/mobsf/.MobSF/tools/jadx/jadx-1.5.0"

if [ -f "${JADX_ZIP}" ]; then
    # 创建目标目录
    mkdir -p "/home/mobsf/.MobSF/tools/jadx"
    
    # 解压 JADX
    unzip -q "${JADX_ZIP}" -d "${JADX_DIR}"
    
    # 设置执行权限
    if [ "$(uname)" != "Windows" ]; then
        echo "为 JADX 目录设置执行权限"
        chmod -R 755 "${JADX_DIR}"
    fi
    
    echo "JADX 安装成功"
else
    echo "错误: ${JADX_ZIP} 不存在"
    exit 1
fi

# # 删除脚本
# rm $0