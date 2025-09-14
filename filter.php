<?php
/**
 * 主函数：执行payload过滤流程
 */
function main() {
    // 读取过滤条件和payload
    $filters = readFileLines('./过滤条件.txt');
    $payloads = readFileLines('./Parameterless_RCE_payload.txt');

    // 定义黑名单
    $blacklist = [' ','\t','\r','\n','\+','\[','\^','\]','\"','\-','\$','\*','\?','\<','\>','\=','\`',];

    // 定义白名单（可以是字符串或数组）
    $whitelist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_();";
    // 或者使用数组形式：
    // $whitelist = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','_','(',')'];


    // 是否启用黑名单（true启用，false禁用）
    $enableBlacklist = true;
    if ($enableBlacklist){
        echo "启用黑名单:";
        echo print_r($blacklist). PHP_EOL;
    }

    // 是否启用白名单（true启用，false禁用）
    $enableWhitelist = true;
    if ($enableWhitelist){
        echo "启用白名单:";
        echo print_r($whitelist). PHP_EOL;
    }

    // 创建唯一文件名
    $filename = 'payload_' . date('Ymd_His') . '.txt';
    $outputFile = fopen($filename, 'w');
    if (!$outputFile) {
        die("错误: 无法创建输出文件 {$filename}");
    }

    echo "payload:". PHP_EOL;
    // 处理每个payload
    foreach ($payloads as $payload) {
        processPayload($payload, $filters, $blacklist, $whitelist, $enableBlacklist, $enableWhitelist,$outputFile);
    }
    fclose($outputFile);
    echo "结果已保存到: {$filename}" . PHP_EOL;
}

/**
 * 读取文件内容并按行返回数组
 * @param string $filename 文件名
 * @return array 文件行数组
 */
function readFileLines($filename) {
    if (!file_exists($filename)) {
        die("错误: 文件 {$filename} 不存在");
    }

    return file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

/**
 * 检查payload是否在黑名单中
 * @param string $payload 待检查的payload
 * @param array $blacklist 黑名单数组
 * @return bool 是否在黑名单中
 */
function isBlacklisted($payload, $blacklist) {
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/', $payload)) {
            return true;
        }
    }
    return false;
}

/**
 * 检查payload是否符合白名单要求
 * @param string $payload 待检查的payload
 * @param string|array $whitelist 白名单（字符串或数组）
 * @return bool 是否符合白名单要求
 */
function isWhitelisted($payload, $whitelist) {
    // 如果白名单是字符串，转换为数组（每个字符为一个元素）
    if (is_string($whitelist)) {
        $whitelist = str_split($whitelist);
    }

    // 检查payload中的每个字符是否都在白名单中
    for ($i = 0; $i < strlen($payload); $i++) {
        $char = $payload[$i];
        $found = false;

        // 检查字符是否在白名单中
        foreach ($whitelist as $allowed) {
            // 处理特殊字符（如'\t'）
            if ($allowed[0] === '\\') {
                // 处理转义序列
                $specialChar = '';
                switch ($allowed[1]) {
                    case 't': $specialChar = "\t"; break;
                    case 'r': $specialChar = "\r"; break;
                    case 'n': $specialChar = "\n"; break;
                    // 添加其他需要的转义序列
                    default: $specialChar = $allowed[1]; break;
                }

                if ($char === $specialChar) {
                    $found = true;
                    break;
                }
            } else {
                // 普通字符直接比较
                if ($char === $allowed) {
                    $found = true;
                    break;
                }
            }
        }

        if (!$found) {
            return false;
        }
    }
    return true;
}

/**
 * 从过滤条件字符串中提取表达式
 * @param string $filter 过滤条件字符串
 * @return string|null 提取的表达式或null
 */
function extractExpression($filter) {
    preg_match('/if\s*\((.*)\)/', $filter, $matches);
    return empty($matches) ? null : $matches[1];
}

/**
 * 替换表达式中的变量为实际payload
 * @param string $expression 条件表达式
 * @param string $payload 实际payload
 * @return string 替换后的表达式
 */
function replaceVariables($expression, $payload) {
    return preg_replace_callback(
        '/(\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*(?:\[[^\]]+\])?)/',
        function($matches) use ($payload) {
            return var_export($payload, true);
        },
        $expression
    );
}

/**
 * 评估过滤条件表达式
 * @param string $expression 条件表达式
 * @return bool 条件是否通过
 */
function evaluateExpression($expression) {
    try {
        return eval("return $expression;");
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * 处理单个payload
 * @param string $payload 待处理的payload
 * @param array $filters 过滤条件数组
 * @param array $blacklist 黑名单数组
 * @param string $whitelist 白名单字符集合
 * @param bool $enableBlacklist 是否启用黑名单检查
 * @param bool $enableWhitelist 是否启用白名单检查
 */
function processPayload($payload, $filters, $blacklist, $whitelist, $enableBlacklist, $enableWhitelist, $outputFile) {
    // 黑名单检查（如果启用）
    if ($enableBlacklist && isBlacklisted($payload, $blacklist)) {
        return;
    }

    // 白名单检查（如果启用）
    if ($enableWhitelist && !isWhitelisted($payload, $whitelist)) {
        return;
    }

    // 检查所有过滤条件
    $passedAllFilters = true;
    foreach ($filters as $filter) {
        $expression = extractExpression($filter);
        if ($expression === null) {
            continue;
        }

        $expression = replaceVariables($expression, $payload);
        if (!evaluateExpression($expression)) {
            $passedAllFilters = false;
            break;
        }
    }

    // 输出通过所有过滤条件的payload
    if ($passedAllFilters) {
        echo $payload . PHP_EOL;
        fwrite($outputFile, $payload . PHP_EOL);
    }
}

// 执行主函数
main();
?>