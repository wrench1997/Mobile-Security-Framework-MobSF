import logging

logger = logging.getLogger(__name__)

# List taken from
# https://developer.apple.com/library/archive/documentation/
# General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html

COCOA_KEYS = {
    'NETestAppMapping': (
        ('允许在不使用MDM服务器的情况下测试每个应用的VPN应用扩展。'),
        'normal'),
    'NFCReaderUsageDescription': (
        '访问设备的NFC读取器。',
        'dangerous'),
    'NSAppleMusicUsageDescription': (
        '访问苹果媒体库。',
        'dangerous'),
    'NSBluetoothPeripheralUsageDescription': (
        '访问蓝牙接口。',
        'dangerous'),
    'NSCalendarsUsageDescription': (
        '访问日历。',
        'dangerous'),
    'NSCameraUsageDescription': (
        '访问相机。',
        'dangerous'),
    'NSContactsUsageDescription': (
        '访问联系人。',
        'dangerous'),
    'NSFaceIDUsageDescription': (
        '访问Face ID认证功能。',
        'normal'),
    'NSHealthClinicalHealthRecordsShareUsageDescription': (
        '访问用户的临床健康记录。',
        'dangerous'),
    'NSHealthShareUsageDescription': (
        '读取健康数据。',
        'dangerous'),
    'NSHealthUpdateUsageDescription': (
        '写入健康数据。',
        'dangerous'),
    'NSHomeKitUsageDescription': (
        '访问HomeKit配置数据。',
        'dangerous'),
    'NSLocationAlwaysUsageDescription': (
        '随时访问位置信息。',
        'dangerous'),
    'NSLocationUsageDescription': (
        '随时访问位置信息（iOS 8以下版本）。',
        'dangerous'),
    'NSLocationWhenInUseUsageDescription': (
        '在应用前台运行时访问位置信息。',
        'dangerous'),
    'NSMicrophoneUsageDescription': (
        '访问麦克风。',
        'dangerous'),
    'NSMotionUsageDescription': (
        '访问设备的加速度计。',
        'dangerous'),
    'NSPhotoLibraryUsageDescription': (
        '访问用户的照片库。',
        'dangerous'),
    'NSRemindersUsageDescription': (
        '访问用户的提醒事项。',
        'dangerous'),
    'NSSiriUsageDescription': (
        '允许应用向Siri发送用户数据',
        'dangerous'),
    'NSSpeechRecognitionUsageDescription': (
        '允许应用向苹果的语音识别服务器发送用户数据。',
        'normal'),
    'NSVideoSubscriberAccountUsageDescription': (
        '访问用户的电视提供商账户。',
        'normal'),
    'NSLocalNetworkUsageDescription': (
        '允许应用请求访问本地网络。',
        'normnal'),
}

def check_permissions(p_list):
    """Check the permissions the app requests."""
    permissions = {}
    for perm, desc in COCOA_KEYS.items():
        if perm in p_list:
            permissions[perm] = {
                'info': desc[0],
                'status': desc[1],
                'description': p_list.get(perm, ''),
            }
    return permissions
