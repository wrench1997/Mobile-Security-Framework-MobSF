import yaml
import os
import time
import random
import requests
import json
from tqdm import tqdm

def translate_rules(input_file, output_file, api_url="http://192.168.166.8:5000/v1/chat/completions"):
    """
    使用大模型API翻译YAML文件中的message字段
    
    参数:
    input_file -- 输入YAML文件路径
    output_file -- 输出YAML文件路径
    api_url -- 大模型API的URL
    """
    # 读取YAML文件
    with open(input_file, 'r', encoding='utf-8') as file:
        rules = yaml.safe_load(file)
    
    # 创建进度条
    total_rules = len(rules)
    pbar = tqdm(total=total_rules, desc="翻译进度")
    
    # 翻译每个规则的message字段
    for i, rule in enumerate(rules):
        if 'message' in rule:
            # 获取原始消息
            original_message = rule['message']
            
            # 添加重试机制
            max_retries = 5
            retry_count = 0
            success = False
            
            while retry_count < max_retries and not success:
                try:
                    # 添加随机延时，避免请求过于频繁
                    delay_time = random.uniform(2.0, 5.0)
                    time.sleep(delay_time)
                    
                    # 构建请求数据
                    request_data = {
                        "model": "claude-3.7-sonnet",
                        "messages": [
                            {
                                "role": "user",
                                "content": f"请将以下英文文本翻译成中文，保持专业准确，不要添加任何解释：\n\n{original_message}"
                            }
                        ],
                        "stream": True
                    }
                    
                    # 发送请求
                    response = requests.post(
                        api_url,
                        headers={"Content-Type": "application/json"},
                        json=request_data,
                        stream=True
                    )
                    
                    # 处理流式响应
                    translated_message = ""
                    for line in response.iter_lines():
                        if line:
                            line = line.decode('utf-8')
                            if line.startswith('data: '):
                                try:
                                    data = json.loads(line[6:])
                                    if 'choices' in data and len(data['choices']) > 0:
                                        delta = data['choices'][0].get('delta', {})
                                        if 'content' in delta:
                                            translated_message += delta['content']
                                except json.JSONDecodeError:
                                    continue
                    
                    # 清理翻译结果（去除可能的引号和多余空格）
                    translated_message = translated_message.strip()
                    if translated_message.startswith('"') and translated_message.endswith('"'):
                        translated_message = translated_message[1:-1]
                    
                    # 更新规则
                    rule['message'] = translated_message
                    print(f"已翻译 ({i+1}/{total_rules}): {original_message} -> {translated_message}")
                    success = True
                    
                except Exception as e:
                    retry_count += 1
                    print(f"翻译失败: {original_message}, 错误: {str(e)}")
                    print(f"尝试重试 ({retry_count}/{max_retries})...")
                    
                    # 如果失败，增加延时时间
                    time.sleep(random.uniform(5.0, 10.0))
            
            # 如果所有重试都失败，保留原文
            if not success:
                print(f"所有重试均失败，保留原文: {original_message}")
        
        # 每翻译10个规则，保存一次中间结果，防止中途失败
        if (i + 1) % 10 == 0:
            with open(f"{output_file}.temp", 'w', encoding='utf-8') as temp_file:
                yaml.dump(rules, temp_file, allow_unicode=True, default_flow_style=False)
            print(f"已保存临时结果到 {output_file}.temp")
        
        # 更新进度条
        pbar.update(1)
    
    # 关闭进度条
    pbar.close()
    
    # 保存翻译后的YAML文件
    with open(output_file, 'w', encoding='utf-8') as file:
        yaml.dump(rules, file, allow_unicode=True, default_flow_style=False)
    
    print(f"翻译完成，已保存到 {output_file}")

if __name__ == "__main__":
    # 输入和输出文件路径
    input_file = "behaviour_rules.yaml"
    output_file = "behaviour_rules_zh.yaml"
    
    # API服务器地址
    api_url = "http://192.168.166.8:5000/v1/chat/completions"
    
    # 执行翻译
    translate_rules(input_file, output_file, api_url)
