#!/usr/bin/env python3
"""
HTTP参数Fuzzer工具（支持GET/POST和随机Payload爆破）
用法: python3 fuzzer.py
"""

import sys
import json
import requests
import os
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def load_config(config_path):
    """加载JSON配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"配置错误: {str(e)}")

def parse_request(request_file):
    """解析HTTP请求文件，返回方法、URL、头部和请求体"""
    try:
        with open(request_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        sys.exit(f"请求文件错误: {str(e)}")
    
    # 提取Host头
    host_match = re.search(r'Host:\s*([^\r\n]+)', content)
    if not host_match:
        sys.exit("错误: 请求包中缺少Host头")
    
    host = host_match.group(1).strip()
    
    # 提取请求行
    request_line_match = re.search(r'^(GET|POST)\s+([^\s]+)', content)
    if not request_line_match:
        sys.exit("错误: 无效的请求行")
    
    method = request_line_match.group(1)
    path = request_line_match.group(2)
    
    # 构建完整URL
    url = f"http://{host}{path}"
    
    # 解析请求头
    headers = {}
    body = ""
    lines = content.splitlines()
    body_started = False
    
    for i, line in enumerate(lines[1:]):
        if not line.strip():
            # 空行后是请求体
            body_started = True
            continue
            
        if body_started:
            # 收集请求体内容
            body += line + "\n"
        else:
            # 解析请求头
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
    
    return method, url, headers, body.strip()

def load_payloads(payload_file):
    """加载payload列表"""
    try:
        with open(payload_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        sys.exit(f"Payload文件错误: {str(e)}")

def is_random_payload(payload):
    """检测Payload是否包含随机特性"""
    patterns = [
        r"array_rand\(",
        r"chr\s*\(\s*ord\s*\(",
        r"crypt\(",
        r"rand\(",
        r"mt_rand\(",
        r"random_",
        r"shuffle\("
    ]
    return any(re.search(pattern, payload) for pattern in patterns)

def build_request_data(method, original_url, param_name, payload, original_body):
    """根据方法构建请求数据"""
    if method == "GET":
        # 构建GET请求URL
        parsed = urlparse(original_url)
        query_dict = parse_qs(parsed.query)
        query_dict[param_name] = payload
        new_query = urlencode(query_dict, doseq=True)
        url = urlunparse(parsed._replace(query=new_query))
        return url, None
    
    elif method == "POST":
        # 构建POST请求体
        if original_body:
            # 解析原始请求体
            body_params = parse_qs(original_body)
            body_params[param_name] = payload
            body = urlencode(body_params, doseq=True)
        else:
            # 如果没有原始请求体，创建新的
            body = f"{param_name}={payload}"
        
        return original_url, body
    
    else:
        sys.exit(f"错误: 不支持的HTTP方法 {method}")

def send_request(method, url, headers, data=None):
    """发送HTTP请求"""
    try:
        if method == "GET":
            return requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=False
            )
        elif method == "POST":
            return requests.post(
                url,
                headers=headers,
                data=data,
                timeout=10,
                verify=False
            )
        else:
            sys.exit(f"错误: 不支持的HTTP方法 {method}")
    except Exception as e:
        print(f"请求失败: {str(e)}")
        return None

def contains_keywords(text, keywords):
    """检查文本中是否包含关键词"""
    if not text or not keywords:
        return False
    return any(keyword.lower() in text.lower() for keyword in keywords)

def save_response(response, payload, blast_index=None):
    """保存响应到文件"""
    os.makedirs("result", exist_ok=True)
    safe_payload = re.sub(r'\W+', '', payload)[:10]
    
    # 文件名处理
    if blast_index is not None:
        filename = f"result/{int(time.time())}_{safe_payload}_blast_{blast_index}.html"
    else:
        filename = f"result/{int(time.time())}_{safe_payload}.html"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(response.text)
    
    return filename

def execute_payload_blast(method, url, headers, data, payload, keywords, blast_count=1):
    """执行Payload爆破"""
    hits = 0
    saved_files = []
    
    for i in range(blast_count):
        print(f"    [{i+1}/{blast_count}] 发送请求...")
        response = send_request(method, url, headers, data)
        
        if not response:
            print("        请求失败")
            continue
        
        print(f"        状态: {response.status_code}, 大小: {len(response.content)}字节")
        
        # 检查关键词
        if contains_keywords(response.text, keywords):
            filename = save_response(response, payload, i+1)
            saved_files.append(filename)
            hits += 1
            print(f"        发现关键词! 响应已保存到: {filename}")
    
    return hits, saved_files

def main():
    """主函数"""
    if len(sys.argv) != 1:
        sys.exit("用法: python3 fuzzer.py")
    
    # 加载配置
    config_path = "./config.json"
    config = load_config(config_path)
    
    # 解析请求
    req_method, base_url, headers, req_body = parse_request(config["Request_Packet_dir"])
    
    # 验证方法
    method = config["http_method"].upper()
    if method != req_method:
        print(f"警告: 配置方法({method})与请求包方法({req_method})不一致")
    
    # 加载payloads
    payloads = load_payloads(config["payload_dir"])
    
    # 获取关键词
    keywords = config.get("key_words", [])
    
    # 分类payloads
    non_random_payloads = []
    random_payloads = []
    
    for payload in payloads:
        if is_random_payload(payload):
            random_payloads.append(payload)
        else:
            non_random_payloads.append(payload)
    
    # 先处理非随机payloads
    print("\n" + "="*50)
    print("处理非随机Payloads")
    print("="*50)
    
    for payload in non_random_payloads:
        print(f"\nPayload: {payload}")
        
        # 构建请求数据
        url, data = build_request_data(
            method, 
            base_url, 
            config["param"], 
            payload, 
            req_body
        )
        
        print(f"URL: {url}")
        if method == "POST":
            print(f"POST数据: {data}")
        
        # 执行单次请求
        response = send_request(method, url, headers, data)
        
        if not response:
            print("    状态: 请求失败")
            continue
        
        print(f"    状态: {response.status_code}")
        print(f"    大小: {len(response.content)}字节")
        
        # 检查关键词
        if contains_keywords(response.text, keywords):
            filename = save_response(response, payload)
            print(f"    发现关键词! 响应已保存到: {filename}")
    
    # 再处理随机特性payloads
    print("\n" + "="*50)
    print("处理随机特性Payloads（爆破）")
    print("="*50)
    
    for payload in random_payloads:
        print(f"\nPayload: {payload}")
        
        # 构建请求数据
        url, data = build_request_data(
            method, 
            base_url, 
            config["param"], 
            payload, 
            req_body
        )
        
        print(f"URL: {url}")
        if method == "POST":
            print(f"POST数据: {data}")
        
        # 执行爆破
        print("    检测到随机Payload，执行爆破")
        hits, saved_files = execute_payload_blast(
            method, url, headers, data, payload, keywords, blast_count=10
        )
        print(f"    爆破完成: {hits}次命中关键词")
        if hits > 0:
            print(f"    保存的文件: {', '.join(saved_files)}")

if __name__ == "__main__":
    main()