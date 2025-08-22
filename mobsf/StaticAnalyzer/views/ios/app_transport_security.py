def check_transport_security(p_list):
    """检查info.plist中的不安全连接配置。"""
    ats = []
    if 'NSAppTransportSecurity' in p_list:
        ats_dict = p_list['NSAppTransportSecurity']
        if ats_dict and ats_dict.get('NSAllowsArbitraryLoads'):
            ats.append({
                'issue': '应用传输安全(ATS)允许任意加载',
                'severity': 'high',
                'description': (
                    '应用传输安全限制对所有网络连接都被禁用。禁用ATS意味着'
                    '允许不安全的HTTP连接。HTTPS连接也被允许，并且仍然受到'
                    '默认服务器信任评估的约束。然而，扩展的安全检查（如要求'
                    '最低传输层安全(TLS)协议版本）被禁用。此设置不适用于'
                    'NSExceptionDomains中列出的域名。'),
            })
        if ats_dict and ats_dict.get('NSAllowsArbitraryLoadsForMedia'):
            ats.append({
                'issue': '允许不安全的媒体加载',
                'severity': 'high',
                'description': (
                    '对于使用AVFoundation框架加载的媒体，应用传输安全限制被禁用，'
                    '而不影响您的URLSession连接。此设置不适用于'
                    'NSExceptionDomains中列出的域名。'),
            })
        if ats_dict and ats_dict.get('NSAllowsArbitraryLoadsInWebContent'):
            ats.append({
                'issue': '允许WebView不安全加载',
                'severity': 'high',
                'description': (
                    '对于从WebView发出的请求，应用传输安全限制被禁用，'
                    '而不影响您的URLSession连接。此设置不适用于'
                    'NSExceptionDomains中列出的域名。'),
            })
        if ats_dict and ats_dict.get('NSAllowsLocalNetworking'):
            ats.append({
                'issue': '允许不安全的本地网络连接',
                'severity': 'high',
                'description': (
                    '对于从本地网络发出的请求，应用传输安全限制被禁用，'
                    '而不影响您的URLSession连接。此设置不适用于'
                    'NSExceptionDomains中列出的域名。'),
            })

        # NS域名例外
        if ats_dict and ats_dict.get('NSExceptionDomains'):
            exception_domains = ats_dict.get('NSExceptionDomains')
            ats.append({
                'issue': '域名例外列表',
                'severity': 'info',
                'description': ', '.join(exception_domains.keys()),
            })
            for domain, config in exception_domains.items():
                if not isinstance(config, dict):
                    continue
                old_exp = 'NSTemporaryExceptionAllowsInsecureHTTPLoads'
                old_exp2 = 'NSThirdPartyExceptionAllowsInsecureHTTPLoads'
                if (config.get('NSExceptionAllowsInsecureHTTPLoads', False)
                        or config.get(old_exp, False)
                        or config.get(old_exp2, False)):
                    if domain in {'localhost', '127.0.0.1'}:
                        continue
                    findings = {
                        'issue': ('允许与{}进行不安全通信'.format(domain)),
                        'severity': 'high',
                        'description': (
                            'NSExceptionAllowsInsecureHTTPLoads允许'
                            '对{}进行不安全的HTTP加载，'
                            '或者放宽对该域名的HTTPS连接的'
                            '服务器信任评估要求。'.format(domain)
                        ),
                    }
                    ats.append(findings)

                if config.get('NSIncludesSubdomains', False):
                    findings = {
                        'issue': ('{}的NSIncludesSubdomains设置为TRUE'.format(domain)),
                        'severity': 'info',
                        'description': (
                            'NSIncludesSubdomains将给定域名的ATS例外'
                            '应用于所有子域名。'
                            '例如，域名例外字典中的ATS例外适用于{}，'
                            '以及math.{}、history.{}等。'
                            '否则，如果值为NO，则例外仅适用于'
                            '{}。'.format(domain, domain, domain, domain)
                        ),
                    }
                    ats.append(findings)
                old_tls = 'NSTemporaryExceptionMinimumTLSVersion'
                inc_min_tls = (config.get('NSExceptionMinimumTLSVersion', None)
                               or config.get(old_tls, None))
                if inc_min_tls in ['TLSv1.0', 'TLSv1.1']:
                    findings = {
                        'issue': ('{}的NSExceptionMinimumTLSVersion设置为{}'
                                  .format(domain, inc_min_tls)),
                        'severity': 'high',
                        'description': (
                            '发送到{}的网络连接的'
                            '最低传输层安全(TLS)版本'
                            '设置为{}。此版本被认为'
                            '是不安全的'.format(domain, inc_min_tls)
                        ),
                    }
                    ats.append(findings)

                elif inc_min_tls == 'TLSv1.2':
                    findings = {
                        'issue': ('{}的NSExceptionMinimumTLSVersion设置为{}'
                                  .format(domain, inc_min_tls)),
                        'severity': 'warning',
                        'description': (
                            '发送到{}的网络连接的'
                            '最低传输层安全(TLS)版本'
                            '设置为{}。'
                            '此版本容易受到'
                            'POODLE、FREAK或'
                            'CurveSwap等攻击。'.format(domain, inc_min_tls)
                        ),
                    }
                    ats.append(findings)

                elif inc_min_tls == 'TLSv1.3':
                    findings = {
                        'issue': ('{}的NSExceptionMinimumTLSVersion设置为{}'
                                  .format(domain, inc_min_tls)),
                        'severity': 'secure',
                        'description': (
                            '发送到{}的网络连接的'
                            '最低传输层安全(TLS)版本'
                            '设置为{}。'.format(domain, inc_min_tls)
                        ),
                    }
                    ats.append(findings)

                elif inc_min_tls is None:
                    pass

                else:
                    findings = {
                        'issue': ('{}的NSExceptionMinimumTLSVersion设置为{}'
                                  .format(domain, inc_min_tls)),
                        'severity': 'info',
                        'description': (
                            '发送到{}的网络连接的'
                            '最低传输层安全(TLS)版本'
                            '设置为{}。'.format(domain, inc_min_tls)
                        ),
                    }
                    ats.append(findings)
                old1 = config.get(
                    'NSTemporaryExceptionRequiresForwardSecrecy', False)
                old2 = config.get(
                    'NSThirdPartyExceptionRequiresForwardSecrecy', False)
                cur = config.get(
                    'NSExceptionRequiresForwardSecrecy', False)
                fsc = [old1, old2, cur]
                if (old1 or old2 or cur) and 'NO' in fsc:
                    findings = {
                        'issue': ('{}的NSExceptionRequiresForwardSecrecy'
                                  '设置为NO'.format(domain)),
                        'severity': 'high',
                        'description': (
                            'NSExceptionRequiresForwardSecrecy'
                            '将接受的密码限制为'
                            '那些通过椭圆曲线Diffie-Hellman'
                            'Ephemeral(ECDHE)密钥交换支持'
                            '完美前向保密(PFS)的密码。'
                            '将此键的值设置为NO可以覆盖'
                            '服务器必须支持给定域名的PFS的要求。'
                            '此键是可选的。默认值为YES，这限制了'
                            '接受的密码为那些通过椭圆曲线Diffie-Hellman'
                            'Ephemeral(ECDHE)密钥交换支持PFS的密码。'),
                    }
                    ats.append(findings)
                ct_tag = config.get('NSRequiresCertificateTransparency', False)
                if not ct_tag or ct_tag == 'NO':
                    findings = {
                        'issue': ('{}的NSRequiresCertificateTransparency'
                                  '设置为NO'.format(domain)),
                        'severity': 'warning',
                        'description': (
                            '证书透明度(CT)是ATS可以用来识别'
                            '错误或恶意颁发的X.509证书的协议。'
                            '将NSRequiresCertificateTransparency键的值'
                            '设置为YES，要求对于给定域名，'
                            '服务器证书由至少两个Apple信任的CT日志'
                            '提供有效的、签名的CT时间戳支持。'
                            '此键是可选的。默认值为NO。'),
                    }
                    ats.append(findings)
                elif ct_tag == 'YES':
                    findings = {
                        'issue': ('{}的NSRequiresCertificateTransparency'
                                  '设置为YES'.format(domain)),
                        'severity': 'secure',
                        'description': (
                            '证书透明度(CT)是ATS可以用来识别'
                            '错误或恶意颁发的X.509证书的协议。'
                            '将NSRequiresCertificateTransparency键的值'
                            '设置为YES，要求对于给定域名，'
                            '服务器证书由至少两个Apple信任的CT日志'
                            '提供有效的、签名的CT时间戳支持。'
                            '此键是可选的。默认值为NO。'),
                    }
                    ats.append(findings)

    return ats