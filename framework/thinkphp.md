# ThinkPHP 代码审计

## 0x00 Introction

版本查看

thinkphp/base.php

```php
define('THINK_VERSION', '5.0.25');
```

## 0x01 基于thinkphp应用的代码审计#

### thinkphp5

框架 rce

[Thinkphp5 RCE总结](https://y4er.com/posts/thinkphp5-rce/)

### thinkphp3

缓存getshell

[ThinkPHP 5.0.10-3.2.3 缓存函数设计缺陷可导致 Getshell](https://paper.seebug.org/374/)

assgin视图渲染 getshell

[](https://xz.aliyun.com/t/10876)

上传误用参数 getshell

[Thinkphp错误使用Upload类导致getshell](https://y4er.com/posts/thinkphp-upload-file/)

where 注入

```php
//1
M('users')->find(I('GET.id'))
//2
$map = array('username' => $_GET['username']);
// $map = array('username' => I('username'));
$user = $User->where($map)->find();
```

[Thinkphp3 漏洞总结](https://y4er.com/posts/thinkphp3-vuln/)

变量可控直接拼接字符串

## 0x03 基于Thinkphp的应用安全分析

...