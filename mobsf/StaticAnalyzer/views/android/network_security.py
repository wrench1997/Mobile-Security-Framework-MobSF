# -*- coding: utf_8 -*-
"""网络安全分析模块。"""
import logging
from pathlib import Path

from defusedxml.minidom import parseString

from mobsf.MobSF.utils import (
    append_scan_status,
    is_path_traversal,
)

logger = logging.getLogger(__name__)
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'


def read_netsec_config(checksum, app_dir, config, src_type):
    """读取清单文件。"""
    msg = '读取网络安全配置'
    try:
        config_file = None
        config = config.replace('@xml/', '', 1)
        base = Path(app_dir)
        if src_type == 'studio':
            # 仅支持Android Studio源文件
            xml_dir = base / 'app' / 'src' / 'main' / 'res' / 'xml'
        else:
            # APK
            xml_dir = base / 'apktool_out' / 'res' / 'xml'
        if not is_path_traversal(config):
            netsec_file = xml_dir / f'{config}.xml'
            if netsec_file.exists():
                desc = f'{msg}，来自{config}.xml'
                logger.info(desc)
                append_scan_status(checksum, desc)
                return netsec_file.read_text('utf8', 'ignore')
        # 无法找到清单中定义的文件
        xmls = Path(xml_dir).glob('*.xml')
        for xml in xmls:
            if 'network_security' in xml.stem:
                config_file = xml
                break
        if not config_file:
            return None
        desc = f'{msg}，来自{config_file.name}'
        logger.info(desc)
        append_scan_status(checksum, desc)
        return config_file.read_text('utf8', 'ignore')
    except Exception as exp:
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return None


def analysis(checksum, app_dir, config, is_debuggable, src_type):
    """执行网络安全分析。"""
    try:
        netsec = {
            'network_findings': [],
            'network_summary': {},
        }
        if not config:
            return netsec
        netsec_conf = read_netsec_config(
            checksum,
            app_dir,
            config,
            src_type)
        if not netsec_conf:
            return netsec
        msg = '解析网络安全配置'
        logger.info(msg)
        append_scan_status(checksum, msg)
        parsed = parseString(netsec_conf)
        finds = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0, SECURE: 0}
        # 基本配置
        b_cfg = parsed.getElementsByTagName('base-config')
        # 0或1个<base-config>
        if b_cfg:
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '基本配置不安全，允许向所有域名发送明文流量。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '基本配置已设置为禁止向所有域名发送明文流量。'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            trst_anch = b_cfg[0].getElementsByTagName('trust-anchors')
            if trst_anch:
                certs = trst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置已设置为信任'
                                f'捆绑的证书 {loc}。'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置已设置为信任'
                                '系统证书。'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置已设置为信任'
                                '用户安装的证书。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置已设置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        # 域名配置
        dom_cfg = parsed.getElementsByTagName('domain-config')
        # 任意数量的<domain-config>
        for cfg in dom_cfg:
            domain_list = []
            domains = cfg.getElementsByTagName('domain')
            for dom in domains:
                domain_list.append(dom.firstChild.nodeValue)
            if cfg.getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        '域名配置不安全，允许向'
                        '这些域名发送明文流量。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            elif cfg.getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        '域名配置安全，禁止向'
                        '这些域名发送明文流量。'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            dtrust = cfg.getElementsByTagName('trust-anchors')
            if dtrust:
                certs = dtrust[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域名配置已设置为信任'
                                f'捆绑的证书 {loc}。'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域名配置已设置为信任'
                                '系统证书。'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域名配置已设置为信任'
                                '用户安装的证书。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域名配置已设置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
            pinsets = cfg.getElementsByTagName('pin-set')
            if pinsets:
                exp = pinsets[0].getAttribute('expiration')
                pins = pinsets[0].getElementsByTagName('pin')
                all_pins = []
                for pin in pins:
                    digest = pin.getAttribute('digest')
                    pin_val = pin.firstChild.nodeValue
                    if digest:
                        tmp = f'Pin: {pin_val} Digest: {digest}'
                    else:
                        tmp = f'Pin: {pin_val}'
                    all_pins.append(tmp)
                pins_list = ','.join(all_pins)
                if exp:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            '证书固定将在'
                            f'{exp}过期。此日期后'
                            '固定将被禁用。'
                            f'[{pins_list}]'),
                        'severity': INFO,
                    })
                    summary[INFO] += 1
                else:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            '证书固定没有'
                            '过期时间。确保'
                            '在证书过期前更新'
                            f'固定值。[{pins_list}]'),
                        'severity': SECURE,
                    })
                    summary[SECURE] += 1
        # 调试覆盖
        de_over = parsed.getElementsByTagName('debug-overrides')
        # 0或1个<debug-overrides>
        if de_over and is_debuggable:
            if de_over[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '调试覆盖已配置为允许向'
                        '所有域名发送明文流量，且应用'
                        '可调试。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            otrst_anch = de_over[0].getElementsByTagName('trust-anchors')
            if otrst_anch:
                certs = otrst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '调试覆盖已配置为信任'
                                f'捆绑的调试证书 {loc}。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '调试覆盖已配置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        netsec['network_findings'] = finds
        netsec['network_summary'] = summary
    except Exception as exp:
        msg = '执行网络安全分析'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return netsec