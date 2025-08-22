MANIFEST_DESC = {
    'well_known_assetlinks': {
        'title': ('未找到应用链接 assetlinks.json 文件'
                  '<br>[android:name=%s]<br>[android:host=%s]'),
        'level': 'high',
        'description': ('未找到应用链接资产验证 URL (%s) 或配置不正确。(状态码: %s)。'
                        '应用链接允许用户从网页 URL/电子邮件重定向到移动应用。'
                        '如果此文件对应用链接主机/域名缺失或配置不正确，'
                        '恶意应用可能会劫持这些 URL。这可能导致钓鱼攻击，'
                        '泄露 URI 中的敏感数据，如个人身份信息、OAuth 令牌、'
                        '魔术链接/密码重置令牌等。您必须通过托管 assetlinks.json '
                        '文件并在 Activity 的 intent-filter 中启用 '
                        '[android:autoVerify="true"] 来验证应用链接域名。'),
        'name': ('未找到应用链接 assetlinks.json 文件 '
                 '[android:name=%s], [android:host=%s]'),
    },
    'clear_text_traffic': {
        'title': ('应用启用了明文流量'
                  '<br>[android:usesCleartextTraffic=true]'),
        'level': 'high',
        'description': ('该应用打算使用明文网络流量，'
                        '如明文 HTTP、FTP 协议栈、DownloadManager '
                        '和 MediaPlayer。针对 API 级别 27 或更低的应用，'
                        '默认值为 "true"。针对 API 级别 28 或更高的应用，'
                        '默认值为 "false"。避免明文流量的主要原因是缺乏'
                        '保密性、真实性和防篡改保护；'
                        '网络攻击者可以窃听传输的数据并且在不被发现的情况下修改它。'),
        'name': ('应用启用了明文流量 '
                 '[android:usesCleartextTraffic=true]'),
    },
    'direct_boot_aware': {
        'title': '应用支持直接启动 <br>[android:directBootAware=true]',
        'level': 'info',
        'description': ('此应用可以在用户解锁设备之前运行。'
                        '如果您使用的是自定义 Application 子类，'
                        '并且应用中的任何组件支持直接启动，'
                        '则整个自定义应用被视为支持直接启动。'
                        '在直接启动期间，您的应用只能访问'
                        '存储在设备保护存储中的数据。'),
        'name': '应用支持直接启动 [android:directBootAware=true]',
    },
    'has_network_security': {
        'title': ('应用具有网络安全配置'
                  '<br>[android:networkSecurityConfig=%s]'),
        'level': 'info',
        'description': ('网络安全配置功能允许应用在安全、'
                        '声明性配置文件中自定义其网络安全设置，'
                        '而无需修改应用代码。这些设置可以为'
                        '特定域名和特定应用进行配置。'),
        'name': ('应用具有网络安全配置 '
                 '[android:networkSecurityConfig=%s]'),
    },
    'vulnerable_os_version': {
        'title': ('应用可以安装在未修补的易受攻击的 '
                  'Android 版本上<br>Android %s, [minSdk=%s]'),
        'level': 'high',
        'description': ('此应用可以安装在旧版 Android 上，'
                        '这些版本存在多个未修复的漏洞。'
                        '这些设备不会从 Google 接收合理的安全更新。'
                        '支持 Android 版本 >= 10, API 29 '
                        '以接收合理的安全更新。'),
        'name': ('应用可以安装在未修补的易受攻击的 '
                 'Android 版本上 %s, [minSdk=%s]'),
    },
    'vulnerable_os_version2': {
        'title': ('应用可以安装在易受攻击的 Android 版本上'
                  '<br>Android %s, minSdk=%s]'),
        'level': 'warning',
        'description': ('此应用可以安装在旧版 Android 上，'
                        '这些版本存在多个漏洞。'
                        '支持 Android 版本 >= 10, API 29 '
                        '以接收合理的安全更新。'),
        'name': ('应用可以安装在易受攻击的 Android 版本上'
                 ' %s, [minSdk=%s]'),
    },
    'app_is_debuggable': {
        'title': '应用启用了调试<br>[android:debuggable=true]',
        'level': 'high',
        'description': ('应用启用了调试，这使得逆向工程师'
                        '更容易连接调试器。这允许转储堆栈跟踪'
                        '并访问调试辅助类。'),
        'name': '应用启用了调试 [android:debuggable=true]',
    },
    'app_allowbackup': {
        'title': ('应用数据可以被备份'
                  '<br>[android:allowBackup=true]'),
        'level': 'warning',
        'description': ('此标志允许任何人通过 adb 备份您的应用数据。'
                        '它允许启用了 USB 调试的用户'
                        '从设备复制应用数据。'),
        'name': '应用数据可以被备份 [android:allowBackup=true]',
    },
    'allowbackup_not_set': {
        'title': ('应用数据可以被备份<br>[android:allowBackup]'
                  ' 标志缺失。'),
        'level': 'warning',
        'description': ('应该将 [android:allowBackup] 标志设置为 false。'
                        '默认情况下，它设置为 true，允许任何人'
                        '通过 adb 备份您的应用数据。它允许'
                        '启用了 USB 调试的用户从设备复制应用数据。'),
        'name': ('应用数据可以被备份 [android:allowBackup] 标志'
                 ' 缺失。'),
    },
    'app_in_test_mode': {
        'title': '应用处于测试模式 <br>[android:testOnly=true]',
        'level': 'high',
        'description': ('它可能会暴露功能或数据，'
                        '这可能导致安全漏洞。'),
        'name': '应用处于测试模式 [android:testOnly=true]',
    },
    'task_affinity_set': {
        'title': '为活动设置了任务亲和性 <br>(%s)',
        'level': 'warning',
        'description': ('如果设置了任务亲和性，'
                        '其他应用可能会读取发送到'
                        '属于另一个任务的活动的意图。'
                        '始终使用默认设置，将亲和性保持为包名，'
                        '以防止其他应用读取发送或接收的意图中的'
                        '敏感信息。'),
        'name': '为活动设置了任务亲和性 (%s)',
    },
    'non_standard_launchmode': {
        'title': '活动 (%s) 的启动模式不是标准的。',
        'level': 'warning',
        'description': ('活动不应将启动模式属性设置为 '
                        '"singleTask/singleInstance"，'
                        '因为它会成为根活动，其他应用可能会'
                        '读取调用意图的内容。因此，当意图中'
                        '包含敏感信息时，需要使用 "standard" '
                        '启动模式属性。'),
        'name': '活动 (%s) 的启动模式不是标准的。',
    },
    'task_hijacking': {
        'title': ('活动 (%s) 容易受到 Android '
                  '任务劫持/StrandHogg 攻击。'),
        'level': 'high',
        'description': ('活动不应将启动模式属性设置为 "singleTask"。'
                        '这样其他应用可能会在活动堆栈顶部放置'
                        '恶意活动，导致任务劫持/StrandHogg 1.0 '
                        '漏洞。这使应用容易受到钓鱼攻击。'
                        '可以通过将启动模式属性设置为 "singleInstance" '
                        '或设置空任务亲和性 (taskAffinity="") 属性来修复此漏洞。'
                        '您还可以将应用的目标 SDK 版本 (%s) 更新到 28 或更高'
                        '以在平台级别修复此问题。'),
        'name': ('活动 (%s) 容易受到 Android '
                 '任务劫持/StrandHogg 攻击。'),
    },
    'task_hijacking2': {
        'title': '活动 (%s) 容易受到 StrandHogg 2.0 攻击',
        'level': 'high',
        'description': ('发现活动容易受到 '
                        'StrandHogg 2.0 任务劫持漏洞。'
                        '当存在漏洞时，其他应用可能会在'
                        '易受攻击应用的活动堆栈顶部放置恶意活动。'
                        '这使应用容易受到钓鱼攻击。可以通过'
                        '将启动模式属性设置为 "singleInstance" '
                        '并设置空任务亲和性 (taskAffinity="") 来修复此漏洞。'
                        '您还可以将应用的目标 SDK 版本 (%s) 更新到 29 或更高'
                        '以在平台级别修复此问题。'),
        'name': '活动 (%s) 容易受到 StrandHogg 2.0 攻击',
    },
    'improper_provider_permission': {
        'title': '不当的内容提供者权限<br>[%s]',
        'level': 'warning',
        'description': ('内容提供者权限被设置为允许'
                        '设备上的任何其他应用访问。'
                        '内容提供者可能包含有关应用的'
                        '敏感信息，因此不应共享。'),
        'name': '不当的内容提供者权限',
    },
    'dialer_code_found': {
        'title': ('发现拨号器代码: %s'
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'warning',
        'description': ('在清单中发现了一个秘密代码。这些代码'
                        '在输入拨号器后，可以授予访问'
                        '可能包含敏感信息的隐藏内容的权限。'),
        'name': ('发现拨号器代码: %s。'
                 ' [android:scheme="android_secret_code"]'),
    },
    'sms_receiver_port_found': {
        'title': '在端口上设置了数据短信接收器: %s <br>[android:port]',
        'level': 'warning',
        'description': ('配置了二进制短信接收器以监听端口。'
                        '发送到设备的二进制短信消息'
                        '由应用以开发者选择的方式处理。'
                        '应用应该正确验证此短信中的数据。'
                        '此外，应用应该假设接收到的短信'
                        '来自不受信任的来源。'),
        'name': '在端口上设置了数据短信接收器: %s。 [android:port]',
    },
    'high_intent_priority_found': {
        'title': '高意图优先级 (%s) - {%s} 命中<br>[android:priority]',
        'level': 'warning',
        'description': ('通过将意图优先级设置为高于'
                        '另一个意图，应用有效地覆盖'
                        '其他请求。'),
        'name': '高意图优先级 (%s) - {%s} 命中 [android:priority]',
    },
    'high_action_priority_found': {
        'title': '高操作优先级 (%s)<br>[android:priority] ',
        'level': 'warning',
        'description': ('通过将操作优先级设置为高于'
                        '另一个操作，应用有效地'
                        '覆盖其他请求。'),
        'name': '高操作优先级 (%s)。 [android:priority]',
    },
    'exported_protected_permission_signature': {
        'title': ('<strong>%s</strong> (%s) 受权限保护。'
                  '<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但'
                        '受权限保护。'),
        'name': ('%s %s 受权限保护。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受权限保护。但是，权限的保护级别'
                        '设置为 normal。这意味着恶意应用可以'
                        '请求并获得权限并与组件交互。'
                        '如果设置为 signature，只有使用相同'
                        '证书签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受权限保护。但是，权限的保护级别'
                        '设置为 dangerous。这意味着恶意应用可以'
                        '请求并获得权限并与组件交互。如果'
                        '设置为 signature，只有使用相同证书'
                        '签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但受权限保护。'
                        '但是，权限的保护级别设置为 signatureOrSystem。'
                        '建议使用 signature 级别。Signature 级别'
                        '应该足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_not_defined': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受在分析的应用中未定义的权限保护。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为 normal 或 dangerous，恶意应用'
                        '可以请求并获得权限并与组件交互。'
                        '如果设置为 signature，只有使用相同证书'
                        '签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal_app_level': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。<br>%s <br>'
                  '[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受权限保护。但是，'
                        '权限的保护级别设置为 normal。'
                        '这意味着恶意应用可以请求并获得权限'
                        '并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous_app_level': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受权限保护。但是，'
                        '权限的保护级别设置为 dangerous。'
                        '这意味着恶意应用可以请求并获得权限'
                        '并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护。'
                  '<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但在应用级别'
                        '受权限保护。'),
        'name': ('%s %s 在应用级别受权限保护。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem_app_level': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但在应用级别'
                        '受权限保护。但是，权限的保护级别'
                        '设置为 signatureOrSystem。建议使用'
                        'signature 级别。Signature 级别应该'
                        '足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_app_level': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受在分析的应用中未定义的'
                        '权限保护。因此，应在定义权限的地方'
                        '检查权限的保护级别。如果设置为 normal'
                        ' 或 dangerous，恶意应用可以请求并获得'
                        '权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 ' [%s] [android:exported=true]'),
    },
    'explicitly_exported': {
        'title': ('<strong>%s</strong> (%s) 未受保护。'
                  ' <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'),
        'name': '%s %s 未受保护。 [android:exported=true]',
    },
    'exported_intent_filter_exists': {
        'title': ('<strong>%s</strong> (%s) 未受保护。<br>'
                  '存在 intent-filter。'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        'intent-filter 的存在表明 %s'
                        ' 被明确导出。'),
        'name': '%s %s 未受保护。存在 intent-filter。',
    },
    'exported_provider': {
        'title': ('<strong>%s</strong> (%s) 未受保护。 <br>'
                  '[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它是一个内容提供者，目标 API 级别'
                        '低于 17，这使其默认导出，'
                        '无论应用运行的系统 API 级别如何。'),
        'name': ('%s %s 未受保护。'
                 ' [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_2': {
        'title': ('<strong>%s</strong> (%s) 如果应用在 API 级别'
                  '低于 17 的设备上运行，将不受保护。 <br>[Content Provider, '
                  'targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s %s) 将被导出。在这种情况下，'
                        '它将与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'),
        'name': ('%s %s 如果应用在 API 级别'
                 '低于 17 的设备上运行，将不受保护。'
                 ' [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受权限保护。但是，权限的保护级别'
                        '设置为 normal。这意味着恶意应用可以'
                        '请求并获得权限并与组件交互。'
                        '如果设置为 signature，只有使用相同'
                        '证书签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_danger': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，'
                  '但应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受权限保护。但是，权限的保护级别'
                        '设置为 dangerous。这意味着恶意应用可以'
                        '请求并获得权限并与组件交互。如果'
                        '设置为 signature，只有使用相同证书'
                        '签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。 [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signature': {
        'title': ('<strong>%s</strong> (%s) 受权限保护。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受权限保护。'),
        'name': ('%s %s 受权限保护。 [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，'
                  '但应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, '
                  'targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但受权限保护。'
                        '但是，权限的保护级别设置为 signatureOrSystem。'
                        '建议使用 signature 级别。Signature 级别'
                        '应该足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。 [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_unknown': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它受在分析的应用中未定义的权限保护。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为 normal 或 dangerous，恶意应用'
                        '可以请求并获得权限并与组件交互。'
                        '如果设置为 signature，只有使用相同证书'
                        '签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。 [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_normal_app': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受权限保护。但是，'
                        '权限的保护级别设置为 normal。'
                        '这意味着恶意应用可以请求并获得权限'
                        '并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_danger_appl': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受权限保护。但是，'
                        '权限的保护级别设置为 dangerous。'
                        '这意味着恶意应用可以请求并获得权限'
                        '并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signature_appl': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护。'
                  '<br>%s <br>[Content Provider,'
                  ' targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受权限保护。'),
        'name': ('%s %s 在应用级别受权限保护。'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem_app': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现%s %s 被导出，但在应用级别'
                        '受权限保护。但是，权限的保护级别'
                        '设置为 signatureOrSystem。建议使用'
                        'signature 级别。Signature 级别应该'
                        '足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_unknown_app': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。<br>%s '
                  '<br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现%s %s 与设备上的其他应用共享，'
                        '因此可被设备上的任何其他应用访问。'
                        '它在应用级别受在分析的应用中未定义的'
                        '权限保护。因此，应在定义权限的地方'
                        '检查权限的保护级别。如果设置为 normal'
                        ' 或 dangerous，恶意应用可以请求并获得'
                        '权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，但'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_normal_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，'
                  '但如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者 (%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 normal。这意味着恶意应用可以请求'
                        '并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，'
                 '但如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，'
                  '但如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别。<br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 dangerous。这意味着恶意应用'
                        '可以请求并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护'
                 '，但如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。尽管如此，它'
                        '受权限保护。'),
        'name': ('%s %s 受权限保护。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 signatureOrSystem。建议使用'
                        'signature 级别。Signature 级别应该'
                        '足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但'
                  '如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别。<br>%s <br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受在分析的应用中未定义的权限保护。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为 normal 或 dangerous，恶意应用可以'
                        '请求并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 受权限保护，但'
                 '如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者 (%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 normal。这意味着恶意应用可以请求'
                        '并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 dangerous。这意味着恶意应用'
                        '可以请求并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别。 [%s] '
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护。'
                  '<br>%s<br>'
                  '[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。尽管如此，它'
                        '受权限保护。'),
        'name': ('%s %s 在应用级别受权限保护。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受权限保护。但是，权限的保护级别'
                        '设置为 signatureOrSystem。建议使用'
                        'signature 级别。Signature 级别应该'
                        '足够满足大多数目的，并且不依赖于'
                        '应用安装在设备上的位置。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用级别受权限保护，但'
                  '如果应用在 API 级别低于 17 的设备上运行，'
                  '应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用在 API 级别低于 17 的设备上运行，'
                        '内容提供者(%s) 将被导出。在这种情况下，'
                        '它仍将受在分析的应用中未定义的权限保护。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为 normal 或 dangerous，恶意应用可以'
                        '请求并获得权限并与组件交互。如果设置为 signature，'
                        '只有使用相同证书签名的应用才能获得权限。'),
        'name': ('%s %s 在应用级别受权限保护，'
                 '但如果应用在 API 级别低于 17 的设备上运行，'
                 '应检查权限的保护级别。'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
}