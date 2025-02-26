# XXE 

## 0x00 Introduction
XML外部实体（XXE）攻击发生在应用程序解析用户提供的XML输入时，未正确禁用外部实体加载。攻击者可利用此漏洞：
- 读取本地文件（如/etc/passwd、配置文件）。
- 发起SSRF攻击，探测内网服务或攻击内部系统。
- 在某些情况下，可能导致拒绝服务（DoS）或远程代码执行（需配合其他漏洞）。

## 0x01 危险函数


以下PHP函数/类在错误配置时易引发XXE：

- simplexml_load_string / simplexml_load_file
默认不解析外部实体，但若启用LIBXML_NOENT选项会强制实体替换，导致漏洞。
- DOMDocument::loadXML / DOMDocument::load
若未禁用resolveExternals和substituteEntities，会解析外部实体。
- xml_parse及其系列函数
使用Expat解析器时，若未显式关闭外部实体处理。

## 0x02 漏洞代码
使用simplexml_load_string
```php
$xml = $_POST['xml'];
$data = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
// 攻击者提交以下XML可读取/etc/passwd：
// <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```

```php
$xml = $_GET['xml'];
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
```

>PHP版本差异：PHP 8.0+默认禁用外部实体，但显式处理更安全。