import requests
import json
import time
import os
from pathlib import Path

class MobSFScanner:
    def __init__(self, api_key, base_url="http://localhost:8000"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"Authorization": api_key}
    
    def upload_file(self, file_path):
        """上传文件到MobSF服务器"""
        print(f"[+] 上传文件: {file_path}")
        upload_url = f"{self.base_url}/api/v1/upload"
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            response = requests.post(upload_url, files=files, headers=self.headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"[+] 上传成功! 文件名: {result['file_name']}, 哈希值: {result['hash']}")
            return result
        else:
            print(f"[-] 上传失败: {response.text}")
            return None
    
    def scan_file(self, file_hash, rescan=0):
        """扫描已上传的文件"""
        print(f"[+] 开始扫描文件，哈希值: {file_hash}")
        scan_url = f"{self.base_url}/api/v1/scan"
        data = {"hash": file_hash, "re_scan": rescan}
        
        response = requests.post(scan_url, data=data, headers=self.headers)
        
        if response.status_code == 200:
            print("[+] 扫描请求已提交")
            return True
        else:
            print(f"[-] 扫描请求失败: {response.text}")
            return False
    
    def get_scan_logs(self, file_hash):
        """获取扫描日志"""
        logs_url = f"{self.base_url}/api/v1/scan_logs"
        data = {"hash": file_hash}
        
        response = requests.post(logs_url, data=data, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[-] 获取扫描日志失败: {response.text}")
            return None
    
    def wait_for_scan_completion(self, file_hash, check_interval=5, timeout=300):
        """等待扫描完成"""
        print("[+] 等待扫描完成...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            logs = self.get_scan_logs(file_hash)
            if logs and "logs" in logs:
                # 检查最后一条日志是否表示扫描完成
                last_log = logs["logs"][-1]
                print(f"    当前状态: {last_log['status']}")
                
                if "Completed" in last_log["status"] or "completed" in last_log["status"].lower():
                    print("[+] 扫描完成!")
                    return True
                
                # 检查是否有异常
                if last_log["exception"]:
                    print(f"[-] 扫描异常: {last_log['exception']}")
                    return False
            
            time.sleep(check_interval)
        
        print(f"[-] 扫描超时，已等待 {timeout} 秒")
        return False
    
    def get_scan_report(self, file_hash):
        """获取扫描报告（JSON格式）"""
        print("[+] 获取扫描报告...")
        report_url = f"{self.base_url}/api/v1/report_json"
        data = {"hash": file_hash}
        
        response = requests.post(report_url, data=data, headers=self.headers)
        
        if response.status_code == 200:
            print("[+] 成功获取扫描报告")
            return response.json()
        else:
            print(f"[-] 获取扫描报告失败: {response.text}")
            return None
    
    def get_scorecard(self, file_hash):
        """获取应用安全评分卡"""
        print("[+] 获取安全评分卡...")
        scorecard_url = f"{self.base_url}/api/v1/scorecard"
        data = {"hash": file_hash}
        
        response = requests.post(scorecard_url, data=data, headers=self.headers)
        
        if response.status_code == 200:
            print("[+] 成功获取安全评分卡")
            return response.json()
        else:
            print(f"[-] 获取安全评分卡失败: {response.text}")
            return None
    
    def download_pdf_report(self, file_hash, output_path):
        """下载PDF格式的扫描报告"""
        print("[+] 下载PDF报告...")
        pdf_url = f"{self.base_url}/api/v1/download_pdf"
        data = {"hash": file_hash}
        
        response = requests.post(pdf_url, data=data, headers=self.headers)
        
        if response.status_code == 200:
            with open(output_path, 'wb') as f:
                f.write(response.content)
            print(f"[+] PDF报告已保存至: {output_path}")
            return True
        else:
            print(f"[-] 下载PDF报告失败: {response.text}")
            return False

def main():
    # 配置参数
    API_KEY = "5ba2ba2519d0138339912997de3ef1ce5f4724a799350d328c11559eaa735945"
    BASE_URL = "http://localhost:8000"  # 修改为你的MobSF服务器地址
    APK_PATH = "path/to/your/app.apk"   # 修改为你要扫描的APK文件路径
    
    # 创建输出目录
    output_dir = Path("mobsf_results")
    output_dir.mkdir(exist_ok=True)
    
    # 初始化扫描器
    scanner = MobSFScanner(API_KEY, BASE_URL)
    
    # 上传文件
    upload_result = scanner.upload_file(APK_PATH)
    if not upload_result:
        print("[-] 上传失败，退出程序")
        return
    
    file_hash = upload_result["hash"]
    file_name = upload_result["file_name"]
    
    # 开始扫描
    if not scanner.scan_file(file_hash):
        print("[-] 扫描请求失败，退出程序")
        return
    
    # 等待扫描完成
    if not scanner.wait_for_scan_completion(file_hash):
        print("[-] 扫描未成功完成，但将继续尝试获取可用结果")
    
    # 获取扫描报告（JSON格式）
    report = scanner.get_scan_report(file_hash)
    if report:
        # 保存JSON报告
        json_path = output_dir / f"{file_name}_report.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[+] JSON报告已保存至: {json_path}")
        
        # 打印一些关键发现
        if "findings" in report:
            print("\n[+] 关键安全发现摘要:")
            for category, findings in report["findings"].items():
                if findings:
                    print(f"    - {category}: {len(findings)} 个问题")
    
    # 获取安全评分卡
    scorecard = scanner.get_scorecard(file_hash)
    if scorecard:
        print("\n[+] 安全评分摘要:")
        if "security_score" in scorecard:
            print(f"    总体安全评分: {scorecard['security_score']}")
    
    # 下载PDF报告
    pdf_path = output_dir / f"{file_name}_report.pdf"
    scanner.download_pdf_report(file_hash, pdf_path)
    
    print("\n[+] 扫描流程完成!")

if __name__ == "__main__":
    main()
