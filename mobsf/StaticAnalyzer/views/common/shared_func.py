# -*- coding: utf_8 -*-
"""
共享函数。

为iOS和Android提供共享函数的模块
"""
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import arpy

from django.utils.html import escape
from django.http import HttpResponseRedirect

from mobsf.MobSF import settings
from mobsf.MobSF.security import (
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    EMAIL_REGEX,
    STRINGS_REGEX,
    URL_REGEX,
    append_scan_status,
    is_md5,
    is_path_traversal,
    is_safe_path,
    print_n_send_error_response,
    set_permissions,
)
from mobsf.MobSF.views.scanning import (
    add_to_recent_scan,
    handle_uploaded_file,
)
from mobsf.StaticAnalyzer.views.comparer import (
    generic_compare,
)
from mobsf.StaticAnalyzer.views.common.entropy import (
    get_entropies,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)


logger = logging.getLogger(__name__)
RESERVED_FILE_NAMES = [
    'AndroidManifest.xml',
    'resources.arsc',
    'META-INF/MANIFEST.MF',
    'META-INF/CERT.SF',
    'META-INF/CERT.RSA',
    'META-INF/CERT.DSA',
    'classes.dex']
for i in range(2, 50):
    RESERVED_FILE_NAMES.append(f'classes{i}.dex')


def hash_gen(checksum, app_path) -> tuple:
    """生成并返回sha1和sha256作为元组。"""
    try:
        msg = '生成 Hash 编码'
        logger.info(msg)
        append_scan_status(checksum, msg)
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        block_size = 65536
        with open(app_path, mode='rb') as afile:
            buf = afile.read(block_size)
            while buf:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(block_size)
        sha1val = sha1.hexdigest()
        sha256val = sha256.hexdigest()
        return sha1val, sha256val
    except Exception as exp:
        msg = '生成哈希值失败'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))


def is_reserved_file_conflict(file_path):
    """检查是否有保留文件冲突。"""
    if any(file_path.startswith(i) and file_path != i for i in RESERVED_FILE_NAMES):
        return True
    return False


def unzip(checksum, app_path, ext_path):
    """解压APK。

    解压APK归档文件，同时处理加密文件、保留文件冲突、
    路径遍历（Zip Slip）和权限调整。这里处理了一些恶意软件作者
    和打包工具使用的反分析技术。

    参数:
        checksum (str): 文件的校验和。
        app_path (str): ZIP归档文件的路径。
        ext_path (str): 提取文件的路径。

    返回:
        list: 提取的文件列表，如果发生错误则返回空列表。
    """
    msg = '解压缩文件'
    logger.info(msg)
    append_scan_status(checksum, msg)
    files = []
    original_ext_path = ext_path
    try:
        with zipfile.ZipFile(app_path, 'r') as zipptr:
            files = zipptr.namelist()
            total_size = 0
            stop_fallback_extraction = False
            for fileinfo in zipptr.infolist():
                ext_path = original_ext_path

                # 跳过加密文件
                if fileinfo.flag_bits & 0x1:
                    msg = ('跳过加密文件 '
                           f'{sanitize_for_logging(fileinfo.filename)}')
                    logger.warning(msg)
                    continue

                file_path = fileinfo.filename.rstrip('/\\')  # 移除尾部斜杠

                # 解码文件名
                if not isinstance(file_path, str):
                    file_path = file_path.decode('utf-8', errors='replace')

                # 检查保留文件冲突
                if is_reserved_file_conflict(file_path):
                    ext_path = str(Path(ext_path) / '_conflict_')

                # 处理Zip Slip
                if is_path_traversal(file_path):
                    msg = ('检测到Zip slip。跳过提取'
                           f' {sanitize_for_logging(file_path)}')
                    logger.error(msg)
                    stop_fallback_extraction = True
                    continue

                # 检查解压后的大小
                if not fileinfo.is_dir():
                    total_size += fileinfo.file_size
                    if fileinfo.file_size > settings.ZIP_MAX_UNCOMPRESSED_FILE_SIZE:
                        size_mb = fileinfo.file_size / (1024 * 1024)
                        msg = (f'文件过大 ({size_mb:.2f} MB)。跳过 '
                               f'{sanitize_for_logging(file_path)}')
                        logger.warning(msg)
                    if total_size > settings.ZIP_MAX_UNCOMPRESSED_TOTAL_SIZE:
                        stop_fallback_extraction = True
                        total_size_mb = total_size / (1024 * 1024)
                        msg = ('解压后总大小 '
                               f'({total_size_mb:.2f} MB) 超出限制。'
                               '中止提取。')
                        logger.error(msg)
                        raise Exception(msg)

                # 修复权限
                if fileinfo.is_dir():
                    # 目录应该有rwxr-xr-x (755)权限
                    # 跳过创建目录
                    continue
                else:
                    # 文件应该有rw-r--r-- (644)权限
                    fileinfo.external_attr = (0o100644 << 16) | (
                        fileinfo.external_attr & 0xFFFF)

                # 提取文件
                try:
                    zipptr.extract(file_path, ext_path)
                except Exception:
                    logger.warning(
                        '提取 %s 失败', sanitize_for_logging(file_path))
    except Exception as exp:
        msg = f'解压错误 - {str(exp)}'
        logger.error(msg)
        append_scan_status(checksum, msg, repr(exp))
        # 如果解压后的总文件大小过大
        # 或者检测到zip slip，则不使用操作系统的unzip作为备选方案
        if stop_fallback_extraction:
            return files
        # 使用操作系统的unzip作为备选方案
        ofiles = os_unzip(checksum, app_path, ext_path)
        if not files:
            files = ofiles
    return files


def os_unzip(checksum, app_path, ext_path):
    """使用操作系统工具解压。"""
    msg = '尝试使用操作系统unzip工具解压'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        if platform.system() == 'Windows':
            msg = '解压错误。Windows上尚未实现'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return []
        unzip_b = shutil.which('unzip')
        if not unzip_b:
            msg = '未找到操作系统Unzip工具'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return []
        subprocess.call(
            [unzip_b, '-o', '-q', app_path, '-d', ext_path])
        # 设置权限，打包文件
        # 可能没有适当的权限
        set_permissions(ext_path)
        # 列出解压目录中的文件
        dat = subprocess.check_output([unzip_b, '-qq', '-l', app_path])
        dat = dat.decode('utf-8').split('\n')
        files_det = ['Length   Date   Time   Name']
        return files_det + dat
    except Exception as exp:
        msg = '使用操作系统unzip工具解压错误'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return []


def lipo_thin(checksum, src, dst):
    """精简Fat二进制文件。"""
    new_src = None
    try:
        msg = '精简Fat二进制文件'
        logger.info(msg)
        append_scan_status(checksum, msg)
        lipo = shutil.which('lipo')
        out = Path(dst) / (Path(src).stem + '_thin.a')
        new_src = out.as_posix()
        archs = [
            'armv7', 'armv6', 'arm64', 'x86_64',
            'armv4t', 'armv5', 'armv6m', 'armv7f',
            'armv7s', 'armv7k', 'armv7m', 'armv7em',
            'arm64v8']
        for arch in archs:
            args = [
                lipo,
                src,
                '-thin',
                arch,
                '-output',
                new_src]
            out = subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT)
            if out.returncode == 0:
                break
    except Exception as exp:
        msg = 'lipo Fat二进制精简失败'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))
    return new_src


def ar_os(src, dst):
    out = ''
    """使用操作系统工具提取AR。"""
    cur = os.getcwd()
    try:
        os.chdir(dst)
        out = subprocess.check_output(
            [shutil.which('ar'), 'x', src],
            stderr=subprocess.STDOUT)
    except Exception as exp:
        out = exp.output
    finally:
        os.chdir(cur)
    return out


def ar_extract(checksum, src, dst):
    """提取AR归档。"""
    msg = '提取静态库归档'
    logger.info(msg)
    append_scan_status(checksum, msg)
    try:
        ar = arpy.Archive(src)
        ar.read_all_headers()
        for a, val in ar.archived_files.items():
            # 处理归档滑动攻击
            filtered = a.decode('utf-8', 'ignore')
            if is_path_traversal(filtered):
                msg = f'检测到Zip slip。跳过提取 {filtered}'
                logger.warning(msg)
                append_scan_status(checksum, msg)
                continue
            out = Path(dst) / filtered
            out.write_bytes(val.read())
    except Exception:
        # 可能是Fat二进制文件，需要Mac主机
        msg = '提取.a归档失败'
        logger.warning(msg)
        append_scan_status(checksum, msg)
        # 使用操作系统ar工具
        plat = platform.system()
        os_err = '可能是Fat二进制文件。需要MacOS进行分析'
        if plat == 'Windows':
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        msg = '使用操作系统ar工具处理归档'
        logger.info(msg)
        append_scan_status(checksum, msg)
        exp = ar_os(src, dst)
        if len(exp) > 3 and plat == 'Linux':
            # 无法在Linux中转换FAT二进制
            logger.warning(os_err)
            append_scan_status(checksum, os_err)
            return
        if b'lipo(1)' in exp:
            msg = '识别到Fat二进制归档'
            logger.info(msg)
            append_scan_status(checksum, msg)
            # Fat二进制归档
            try:
                nw_src = lipo_thin(checksum, src, dst)
                if nw_src:
                    ar_os(nw_src, dst)
            except Exception as exp:
                msg = '精简fat归档失败'
                logger.exception(msg)
                append_scan_status(checksum, msg, repr(exp))


def url_n_email_extract(dat, relative_path):
    """从源代码中提取URL和电子邮件。"""
    urls = set()
    emails = set()
    urllist = []
    url_n_file = []
    email_n_file = []
    # URL提取
    urllist = URL_REGEX.findall(dat.lower())
    for url in urllist:
        urls.add(url)
    if urls:
        url_n_file.append({
            'urls': list(urls),
            'path': escape(relative_path)})

    # 电子邮件提取
    for email in EMAIL_REGEX.findall(dat.lower()):
        if not email.startswith('//'):
            emails.add(email)
    if emails:
        email_n_file.append({
            'emails': list(emails),
            'path': escape(relative_path)})
    return urllist, url_n_file, email_n_file


# 这只是触发generic_compare的第一个健全性检查
@login_required
def compare_apps(request, hash1: str, hash2: str, api=False):
    if hash1 == hash2:
        error_msg = '不能比较具有相同哈希值的结果'
        return print_n_send_error_response(request, error_msg, api)
    # REST API的第二次验证
    if not (is_md5(hash1) and is_md5(hash2)):
        error_msg = '无效的哈希值'
        return print_n_send_error_response(request, error_msg, api)
    logger.info(
        '开始比较应用 %s 和 %s', hash1, hash2)
    return generic_compare(request, hash1, hash2, api)


def get_avg_cvss(findings):
    # 平均CVSS分数
    cvss_scores = []
    avg_cvss = 0
    for finding in findings.values():
        find = finding.get('metadata')
        if not find:
            # 支持iOS二进制扫描结果的hack
            find = finding
        if find.get('cvss'):
            if find['cvss'] != 0:
                cvss_scores.append(find['cvss'])
    if cvss_scores:
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1)
    if not getattr(settings, 'CVSS_SCORE_ENABLED', False):
        avg_cvss = None
    return avg_cvss


def find_java_source_folder(base_folder: Path):
    # 为APK/源代码zip找到正确的java/kotlin源文件夹
    # 返回一个元组 - (SRC_PATH, SRC_TYPE, SRC_SYNTAX)
    return next(p for p in [(base_folder / 'java_source',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'java',
                             'java', '*.java'),
                            (base_folder / 'app' / 'src' / 'main' / 'kotlin',
                             'kotlin', '*.kt'),
                            (base_folder / 'src',
                             'java', '*.java')]
                if p[0].exists())


def is_secret_key(key):
    """检查键值对中的键是否有趣。"""
    key_lower = key.lower()
    # 键以这些字符串结尾
    endswith = (
        'api', 'key', 'secret', 'token', 'username',
        'user_name', 'user', 'pass', 'password',
        'private_key', 'access_key',
    )
    # 键包含这些字符串
    contains = (
        'api_', 'key_', 'aws', 's3_', '_s3', 'secret_',
        'bearer', 'jwt', 'certificate"', 'credential',
        'azure', 'webhook', 'twilio_', 'bitcoin',
        '_auth', 'firebase', 'oauth', 'authorization',
        'private', 'pwd', 'session', 'token_', 'gcp',
    )
    # 键不能包含这些字符串
    not_string = (
        'label_', 'text', 'hint', 'msg_', 'create_',
        'message', 'new', 'confirm', 'activity_',
        'forgot', 'dashboard_', 'current_', 'signup',
        'sign_in', 'signin', 'title_', 'welcome_',
        'change_', 'this_', 'the_', 'placeholder',
        'invalid_', 'btn_', 'action_', 'prompt_',
        'lable', 'hide_', 'old', 'update', 'error',
        'empty', 'txt_', 'lbl_',
    )
    not_contains_str = any(i in key_lower for i in not_string)
    contains_str = any(i in key_lower for i in contains)
    endswith_str = any(key_lower.endswith(i) for i in endswith)
    return (endswith_str or contains_str) and not not_contains_str


def strings_and_entropies(checksum, src, exts):
    """获取字符串和熵值。"""
    msg = '从代码中提取字符串值和熵值'
    logger.info(msg)
    append_scan_status(checksum, msg)
    data = {
        'strings': set(),
        'secrets': set(),
    }
    try:
        if not (src and src.exists()):
            return data
        excludes = ('\\u0', 'com.google.')
        eslash = ('Ljava', 'Lkotlin', 'kotlin', 'android')
        for p in src.rglob('*'):
            if p.suffix not in exts or not p.exists():
                continue
            matches = STRINGS_REGEX.finditer(
                p.read_text(encoding='utf-8', errors='ignore'),
                re.MULTILINE)
            for match in matches:
                string = match.group()
                if len(string) < 4:
                    continue
                if any(i in string for i in excludes):
                    continue
                if any(i in string and '/' in string for i in eslash):
                    continue
                if not string[0].isalnum():
                    continue
                data['strings'].add(string)
        if data['strings']:
            data['secrets'] = get_entropies(data['strings'])
    except Exception as exp:
        msg = '从代码中提取字符串值和熵值失败'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return data


def get_symbols(symbols):
    all_symbols = []
    for i in symbols:
        for _, val in i.items():
            all_symbols.extend(val)
    return list(set(all_symbols))


@login_required
@permission_required(Permissions.SCAN)
def scan_library(request, checksum):
    """从路径名扫描共享库或框架。"""
    try:
        libchecksum = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                '无效的MD5')
        relative_path = request.GET['library']
        lib_dir = Path(settings.UPLD_DIR) / checksum

        sfile = lib_dir / relative_path
        if not is_safe_path(lib_dir.as_posix(), sfile.as_posix()):
            msg = '检测到路径遍历！'
            return print_n_send_error_response(request, msg)
        ext = sfile.suffix
        if not ext and 'Frameworks' in relative_path:
            # 在Frameworks上强制使用Dylib
            ext = '.dylib'
        if not sfile.exists():
            msg = '未找到库文件'
            return print_n_send_error_response(request, msg)
        with open(sfile, 'rb') as f:
            libchecksum = handle_uploaded_file(f, ext)
        if ext in [f'.{i}' for i in settings.IOS_EXTS]:
            static_analyzer = 'static_analyzer_ios'
        elif ext == '.appx':
            # 不适用，但仍然设置它
            static_analyzer = 'windows_static_analyzer'
        elif ext in [f'.{i}' for i in settings.ANDROID_EXTS]:
            static_analyzer = 'static_analyzer'
        else:
            msg = '不支持的扩展名'
            return print_n_send_error_response(request, msg)
        data = {
            'analyzer': static_analyzer,
            'status': 'success',
            'hash': libchecksum,
            'scan_type': ext.replace('.', ''),
            'file_name': sfile.name,
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/{static_analyzer}/{libchecksum}/')
    except Exception:
        msg = '无法执行库的静态分析'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)