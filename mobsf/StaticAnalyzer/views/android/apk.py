# -*- coding: utf_8 -*-
"""Android APK和源代码分析。"""
import logging
import shutil
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.android import (
    apkid,
    permissions,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.android.app import (
    aapt_parse,
    androguard_parse,
    get_apk_name,
)
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from mobsf.StaticAnalyzer.views.android.code_analysis import code_analysis
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
    dex_2_smali,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.android.icon_analysis import (
    get_icon_apk,
    get_icon_from_src,
)
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    manifest_analysis,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    extract_manifest_data,
    get_parsed_manifest,
)
from mobsf.StaticAnalyzer.views.android.playstore import (
    get_app_details,
)
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
    hash_gen,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.firebase import (
    firebase_analysis,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)
from mobsf.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    mark_task_completed,
    mark_task_started,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)


def initialize_app_dic(app_dic, file_ext):
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    return checksum


def get_size_and_hashes(app_dic):
    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
    app_dic['sha1'], app_dic['sha256'] = hash_gen(app_dic['md5'], app_dic['app_path'])


def get_manifest_data(app_dic):
    """获取清单数据。"""
    # 解析清单XML
    get_parsed_manifest(app_dic)
    # 填充manifest_file, manifest_namespace, manifest_parsed_xml

    # 提取清单数据
    man_data_dic = extract_manifest_data(app_dic)
    # 清单分析
    man_analysis = manifest_analysis(app_dic, man_data_dic)
    return man_data_dic, man_analysis


def print_scan_subject(app_dic, man_data):
    """记录扫描对象。"""
    checksum = app_dic['md5']
    app_name = app_dic.get('real_name')
    pkg_name = man_data.get('packagename')
    pkg_name2 = app_dic.get('apk_features', {}).get('package')
    if not pkg_name:
        pkg_name = pkg_name2
    subject = 'Android应用'
    if app_name and pkg_name:
        subject = f'{app_name} ({pkg_name})'
    elif pkg_name:
        subject = pkg_name
    elif app_name:
        subject = app_name
    msg = f'正在执行静态分析: {subject}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    if subject == '失败':
        subject = f'({subject})'
    app_dic['subject'] = subject


def clean_up(app_dic):
    """清理以便序列化。"""
    app_dic['androguard_apk'] = None
    app_dic['androguard_apk_resources'] = None


def apk_analysis_task(checksum, app_dic, rescan, queue=False):
    """APK分析任务。"""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        append_scan_status(checksum, '初始化')
        get_size_and_hashes(app_dic)
        msg = '正在提取APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dic['zipped'] = 'apk'
        # 提取APK并获取文件
        app_dic['files'] = unzip(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'])
        # 使用Androguard提取APK数据
        androguard_parse(app_dic)
        # 填充androguard_apk, androguard_manifest_xml, androguard_string_resources
        # 使用AAPT/AAPT2提取APK数据
        aapt_parse(app_dic)  # 填充apk_features, files, apk_strings
        get_hardcoded_cert_keystore(app_dic)  # 填充file_analysis
        # 清单数据
        man_data_dic, man_analysis = get_manifest_data(app_dic)
        # 获取应用名称
        get_apk_name(app_dic)  # 填充real_name
        print_scan_subject(app_dic, man_data_dic)  # 填充subject
        get_app_details(app_dic, man_data_dic)  # 填充playstore
        # 恶意权限检查
        mal_perms = permissions.check_malware_permission(
            checksum,
            man_data_dic['perm'])
        man_analysis['malware_permissions'] = mal_perms
        # 获取图标
        get_icon_apk(app_dic)  # 填充icon_path
        elf_dict = library_analysis(
            checksum,
            app_dic['app_dir'],
            'elf')
        cert_dic = cert_info(app_dic, man_data_dic)
        apkid_results = apkid.apkid_analysis(
            checksum,
            app_dic['app_path'])
        trackers = Trackers.Trackers(
            checksum,
            app_dic['app_dir'],
            app_dic['tools_dir']).get_trackers()
        apk_2_java(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'],
            settings.DOWNLOADED_TOOLS_DIR)
        dex_2_smali(
            checksum,
            app_dic['app_dir'],
            app_dic['tools_dir'])
        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data_dic['perm'])
        # 获取字符串和元数据
        get_strings_metadata(
            app_dic,
            elf_dict['elf_strings'],
            ['.java'],
            code_an_dic)
        # Firebase数据库检查
        code_an_dic['firebase'] = firebase_analysis(
            checksum,
            code_an_dic)
        # 域名提取和恶意软件检查
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_an_dic['urls_list'])
        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_analysis,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            trackers,
            rescan,
        )
        if queue:
            return mark_task_completed(
                checksum, app_dic['subject'], '成功')
        return context, None
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, '失败', repr(exp))
        return context, repr(exp)
    finally:
        # 清理
        clean_up(app_dic)


def generate_dynamic_context(request, app_dic, checksum, context, api):
    """生成动态上下文。"""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis']['findings'])
    logcat_file = Path(app_dic['app_dir']) / 'logcat.txt'
    context['dynamic_analysis_done'] = logcat_file.exists()
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(app_dic['app_path'])
    template = 'static_analysis/android_binary_analysis.html'
    return context if api else render(request, template, context)


def apk_analysis(request, app_dic, rescan, api):
    """APK分析。"""
    checksum = initialize_app_dic(app_dic, 'apk')
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_context(request, app_dic, checksum, context, api)
    else:
        # APK分析
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, '权限被拒绝', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('app_name', ''),
                apk_analysis_task, checksum, app_dic, rescan)
        context, err = apk_analysis_task(checksum, app_dic, rescan)
        if err:
            return print_n_send_error_response(request, err, api)
        return generate_dynamic_context(request, app_dic, checksum, context, api)


def src_analysis_task(checksum, app_dic, rescan, pro_type, queue=False):
    """Android ZIP源代码分析开始。"""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        cert_dic = {
            'certificate_info': '',
            'certificate_status': '',
            'description': '',
        }
        app_dic['strings'] = []
        app_dic['secrets'] = []
        # 上述字段仅适用于APK而非ZIP
        app_dic['zipped'] = pro_type
        get_hardcoded_cert_keystore(app_dic)
        # 清单数据
        man_data_dic, man_analysis = get_manifest_data(app_dic)
        # 获取应用名称
        get_apk_name(app_dic)
        # 打印扫描对象
        print_scan_subject(app_dic, man_data_dic)
        get_app_details(app_dic, man_data_dic)
        # 恶意权限检查
        mal_perms = permissions.check_malware_permission(
            checksum,
            man_data_dic['perm'])
        man_analysis['malware_permissions'] = mal_perms
        # 获取图标
        get_icon_from_src(
            app_dic,
            man_data_dic['icons'])
        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data_dic['perm'])
        # 获取字符串和元数据
        get_strings_metadata(
            app_dic,
            None,
            ['.java', '.kt'],
            code_an_dic)
        # Firebase数据库检查
        code_an_dic['firebase'] = firebase_analysis(
            checksum,
            code_an_dic)
        # 域名提取和恶意软件检查
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_an_dic['urls_list'])
        # 从域名中提取跟踪器
        trackers = Trackers.Trackers(
            checksum,
            None,
            app_dic['tools_dir']).get_trackers_domains_or_deps(
                code_an_dic['domains'], [])
        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_analysis,
            code_an_dic,
            cert_dic,
            [],
            {},
            trackers,
            rescan,
        )
        if queue:
            return mark_task_completed(
                checksum, app_dic['subject'], '成功')
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, '失败', repr(exp))
    return context


def generate_dynamic_src_context(request, context, api):
    """生成动态源代码上下文。"""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis']['findings'])
    template = 'static_analysis/android_source_analysis.html'
    return context if api else render(request, template, context)


def src_analysis(request, app_dic, rescan, api):
    """源代码分析。"""
    checksum = initialize_app_dic(app_dic, 'zip')
    ret = f'/static_analyzer_ios/{checksum}/'
    db_entry = StaticAnalyzerAndroid.objects.filter(
        MD5=checksum)
    ios_db_entry = StaticAnalyzerIOS.objects.filter(
        MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_src_context(request, context, api)
    elif ios_db_entry.exists() and not rescan:
        return {'type': 'ios'} if api else HttpResponseRedirect(ret)
    else:
        # 初始化Android和iOS源代码分析
        append_scan_status(checksum, '初始化')
        get_size_and_hashes(app_dic)
        msg = '正在提取ZIP'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dic['files'] = unzip(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'])
        # 检查是否有效的目录结构并获取ZIP类型
        pro_type, valid = valid_source_code(
            checksum,
            app_dic['app_dir'])
        msg = f'源代码类型 - {pro_type}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        # 处理iOS源代码
        if valid and pro_type == 'ios':
            msg = '重定向到iOS源代码分析器'
            logger.info(msg)
            append_scan_status(checksum, msg)
            ret = f'{ret}?rescan={str(int(rescan))}'
            return {'type': 'ios'} if api else HttpResponseRedirect(ret)
        # Android源代码分析
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                '权限被拒绝',
                False)
        if valid and (pro_type in ['eclipse', 'studio']):
            if settings.ASYNC_ANALYSIS:
                return async_analysis(
                    checksum,
                    api,
                    app_dic.get('app_name', ''),
                    src_analysis_task, checksum, app_dic, rescan, pro_type)
            context = src_analysis_task(checksum, app_dic, rescan, pro_type)
            return generate_dynamic_src_context(request, context, api)
        else:
            msg = '不支持此ZIP格式'
            if api:
                return print_n_send_error_response(
                    request,
                    msg,
                    True)
            else:
                print_n_send_error_response(request, msg, False)
                ctx = {
                    'title': '无效的ZIP归档',
                    'version': settings.MOBSF_VER,
                }
                template = 'general/zip.html'
                return render(request, template, ctx)


def is_android_source(app_path):
    """检测Android源代码和IDE类型。"""
    # Eclipse
    man = app_path / 'AndroidManifest.xml'
    src = app_path / 'src'
    if man.is_file() and src.exists():
        return 'eclipse', True

    # Studio
    man = app_path / 'app' / 'src' / 'main' / 'AndroidManifest.xml'
    java = app_path / 'app' / 'src' / 'main' / 'java'
    kotlin = app_path / 'app' / 'src' / 'main' / 'kotlin'
    if man.is_file() and (java.exists() or kotlin.exists()):
        return 'studio', True

    return None, False


def move_to_parent(inside_path, app_path):
    """将内部内容移动到应用目录。"""
    for item in inside_path.iterdir():
        shutil.move(str(item), str(app_path))
    shutil.rmtree(inside_path)


def valid_source_code(checksum, app_dir):
    """测试这是否是有效的源代码zip。"""
    try:
        msg = '正在检测源代码类型'
        logger.info(msg)
        append_scan_status(checksum, msg)

        app_path = Path(app_dir)
        ide, is_and = is_android_source(app_path)

        if ide:
            return ide, is_and

        # 放宽Android源代码检查，向下一级
        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                ide, is_and = is_android_source(subdir)
                if ide:
                    move_to_parent(subdir, app_path)
                    return ide, is_and

        # iOS源代码
        xcode = [f for f in app_path.iterdir() if f.suffix == '.xcodeproj']
        if xcode:
            return 'ios', True

        # 放宽iOS源代码检查
        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                if any(f.suffix == '.xcodeproj' for f in subdir.iterdir()):
                    return 'ios', True

        return '', False
    except Exception as exp:
        msg = '从zip中识别源代码类型时出错'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))