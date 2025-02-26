# 文件上传

## 0x00 Introduction

文件上传漏洞是指用户上传了一个可执行脚本文件，并通过此文件获得了执行服器端命令的能力。在大多数情况下，文件上传漏洞一般是指上传 WEB 脚本能够被服务器解析的问题，也就是所谓的 webshell 问题。完成这一攻击需要这样几个条件，一是上传的文件能够被 WEB 容器执行，其次用户能从 WEB 上访问这个文件，最后，如果上传的文件被安全检查、格式化、图片压缩等功能改变了内容，则可能导致攻击失败。

## 0x01 危险函数

- `move_uploaded_file()`
核心上传函数，若未验证文件名和内容，直接保存用户输入的文件名，可能导致恶意文件执行。
```php
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_POST['filename']);
```
- `copy() / rename()`
若操作未经验证的用户文件名，可能覆盖敏感文件或写入恶意内容。
```php
copy($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
```
- `file_put_contents()`
直接写入用户可控内容到文件，可能导致代码执行。
```php
file_put_contents("uploads/" . $_POST['name'], $_FILES['file']['tmp_name']);
```

## 0x02 漏洞代码

### 场景1：无任何过滤
```php
$upload_dir = 'uploads/';
$target_file = $upload_dir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target_file);
```

### 场景2：黑名单过滤不严
```php
$deny_ext = array("php", "php5");
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, $deny_ext)) {
    move_uploaded_file(...);
}
```
绕过方法：使用.phtml、.phar、.htaccess（Apache）或大小写如.PHP。

### 场景3：仅验证MIME类型

```php
if ($_FILES['file']['type'] == 'image/jpeg') {
    move_uploaded_file(...);
}
```
绕过方法：伪造HTTP请求的Content-Type为image/jpeg，上传实际为PHP的文件。


### 场景4：路径拼接漏洞（旧版本PHP）
```php
$target = "uploads/" . $_GET['dir'] . "/" . $_FILES['file']['name'];
```




## 0x03 常规防护绕过技巧

### 扩展名绕过

- 双扩展名：shell.jpg.php（Apache可能解析为PHP）。
- 特殊扩展名：.php5、.phtml、.phar。
- 大小写混淆：.PHP、.PhP。
- 空格/点号结尾：shell.php.（Windows自动去除末尾点）。

### 内容伪造

- 添加图片头（如GIF89a）绕过内容检测。
- 利用Exif注释嵌入PHP代码。

### .htaccess文件绕过
在Apache服务器环境中，攻击者通过上传恶意.htaccess文件可篡改目录解析规则，将非可执行文件（如图片）强制解析为PHP脚本，从而绕过文件上传防护。

强制将.jpg文件作为PHP脚本解析。
```
AddType application/x-httpd-php .jpg
```
```
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

### 解析漏洞

- Apache：上传shell.php.jpg配合.htaccess设置AddType application/x-httpd-php .jpg。
- Nginx：路径解析错误（如/uploads/shell.jpg/xxx.php被解析为JPG）。

### 竞争条件攻击
快速访问临时文件（需结合文件包含漏洞）。

