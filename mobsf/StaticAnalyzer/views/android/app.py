# -*- coding: utf_8 -*-
"""APK分析模块。"""
import os
import re
import logging
from pathlib import Path

from mobsf.StaticAnalyzer.tools.androguard4 import (
    apk,
)
from mobsf.StaticAnalyzer.views.android import (
    aapt,
)
from mobsf.MobSF.utils import (
    append_scan_status,
)

logger = logging.getLogger(__name__)


def aapt_parse(app_dict):
    """使用aapt/aapt2从APK中提取特征。"""
    checksum = app_dict['md5']
    app_dict['apk_features'] = {}
    app_dict['apk_strings'] = []
    try:
        msg = '使用aapt/aapt2提取APK特征'
        logger.info(msg)
        append_scan_status(checksum, msg)
        aapt_obj = aapt.AndroidAAPT(app_dict['app_path'])
        app_dict['apk_features'] = aapt_obj.get_apk_features()
        if not app_dict.get('files'):
            app_dict['files'] = aapt_obj.get_apk_files()
        app_dict['apk_strings'] = aapt_obj.get_apk_strings()
    except FileNotFoundError:
        msg = '未找到aapt和aapt2，跳过APK特征提取'
        logger.warning(msg)
        append_scan_status(checksum, msg)
    except Exception as exp:
        msg = '使用aapt/aapt2提取APK特征失败'
        logger.warning(msg)
        append_scan_status(checksum, msg, repr(exp))


def androguard_parse(app_dict):
    """使用androguard从APK中提取特征。"""
    checksum = app_dict['md5']
    app_dict['androguard_apk'] = None
    app_dict['androguard_manifest_xml'] = None
    app_dict['androguard_apk_resources'] = None
    app_dict['androguard_apk_name'] = None
    app_dict['androguard_apk_icon'] = None
    try:
        msg = '使用androguard解析APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        a = apk.APK(app_dict['app_path'])
        if not a:
            msg = '使用androguard解析APK失败'
            logger.warning(msg)
            append_scan_status(checksum, msg)
            return
        app_dict['androguard_apk'] = a
        try:
            app_dict['androguard_apk_name'] = a.get_app_name()
        except Exception as exp:
            msg = '使用androguard获取应用名称失败'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            app_dict['androguard_apk_icon'] = a.get_app_icon(max_dpi=0xFFFE - 1)
        except Exception as exp:
            msg = '使用androguard获取应用图标失败'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            xml = a.get_android_manifest_axml().get_xml()
            app_dict['androguard_manifest_xml'] = xml
        except Exception as exp:
            msg = '使用androguard解析AndroidManifest.xml失败'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
        try:
            app_dict['androguard_apk_resources'] = a.get_android_resources()
        except Exception as exp:
            msg = '使用androguard解析资源失败'
            logger.warning(msg)
            append_scan_status(checksum, msg, repr(exp))
    except Exception as exp:
        msg = '使用androguard解析APK失败'
        logger.error(msg)
        append_scan_status(checksum, msg, repr(exp))


def get_apk_name(app_dic):
    """获取应用名称。"""
    real_name = ''
    base = Path(app_dic['app_dir'])

    # 检查是否为APK并尝试获取应用名称
    if app_dic.get('androguard_apk_name') or app_dic.get('apk_features'):
        app_name = (
            app_dic.get('androguard_apk_name')
            or app_dic.get('apk_features', {}).get('application_label')
        )
        if app_name:
            real_name = app_name
        else:
            # 备选方案：在values文件夹中查找app_name
            values_path = base / 'apktool_out' / 'res' / 'values'
            if values_path.exists():
                try:
                    real_name = get_app_name_from_values_folder(values_path.as_posix())
                except Exception:
                    logger.error('从values文件夹获取应用名称失败')

    # 检查是否为源代码并尝试获取应用名称
    else:
        try:
            # 检查values文件夹的路径
            paths_to_check = [
                base / 'app' / 'src' / 'main' / 'res' / 'values',
                base / 'res' / 'values',
            ]
            for path in paths_to_check:
                if path.exists():
                    real_name = get_app_name_from_values_folder(path.as_posix())
                    break
        except Exception:
            logger.error('从源代码获取应用名称失败')

    if not real_name:
        logger.warning('无法找到应用名称')

    # 更新应用字典
    app_dic['real_name'] = real_name


def get_app_name_from_values_folder(values_dir):
    """获取values文件夹中的所有文件并检查它们是否包含app_name。"""
    files = [f for f in os.listdir(values_dir) if
             (os.path.isfile(os.path.join(values_dir, f)))
             and (f.endswith('.xml'))]
    for f in files:
        # 查看每个文件，搜索app_name
        app_name = get_app_name_from_file(os.path.join(values_dir, f))
        if app_name:
            return app_name  # 我们找到了app_name，返回它
    return ''  # 没有找到app_name，返回空字符串


def get_app_name_from_file(file_path):
    """在特定文件中查找app_name。"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()

    app_name_match = re.search(
        r'<string name=\"app_name\">(.{0,300})</string>',
        data)

    if (not app_name_match) or (len(app_name_match.group()) <= 0):
        # 在当前文件中未找到app_name
        return ''

    # 找到app_name！
    return app_name_match.group(app_name_match.lastindex)