# SQL注入

## 0x00 Introduction
PHP代码审计中的SQL注入是一种常见的安全漏洞，攻击者可以通过构造恶意输入来操纵SQL查询，从而获取、修改或删除数据库中的数据。

## 0x01 危险函数

在PHP中，以下函数或操作容易导致SQL注入漏洞：

- mysql_query(): 旧的MySQL扩展，已弃用，但仍有代码在使用。

- mysqli_query(): MySQLi扩展，如果不正确使用，仍然可能导致SQL注入。

- PDO::query(): PDO扩展，如果不使用预处理语句，也可能导致SQL注入。

## 0x02 漏洞代码

### 直接拼接用户输入
```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysql_query($sql);

if (mysql_num_rows($result) > 0) {
    echo "Login successful!";
} else {
    echo "Invalid credentials!";
}
?>
```
### 使用mysqli_query()但不使用预处理语句

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$conn = new mysqli("localhost", "user", "pass", "db");

$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    echo "Login successful!";
} else {
    echo "Invalid credentials!";
}
?>
```

正确的编码规范

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$conn = new mysqli("localhost", "user", "pass", "db");

$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Login successful!";
} else {
    echo "Invalid credentials!";
}
?>
```

### 二次注入
用户输入在首次存储时被转义或过滤，但在后续从数据库中取出时未正确处理，导致恶意代码被拼接到新的SQL查询中执行。
```php
// 用户注册（输入被转义存储）
$username = mysqli_real_escape_string($conn, $_POST['username']);
$sql = "INSERT INTO users (username) VALUES ('$username')";
mysqli_query($conn, $sql);

// 后续修改密码功能（取出未转义的username拼接到SQL）
$user = getUserFromDatabase($_SESSION['user_id']); // 从数据库取出原始数据
$new_pass = $_POST['new_password'];
$sql = "UPDATE users SET password = '$new_pass' WHERE username = '$user'"; 
// 若$user存储的是恶意值（如 ' OR 1=1 -- ），将导致所有用户密码被修改！
```
利用方式：

1. 用户注册时提交用户名为：`admin' OR 1=1 --`
2. 注册时被转义为 `admin\' OR 1=1 --` 存入数据库
3. 后续修改密码时，从数据库取出未转义的原始值 admin' OR 1=1 -- ，导致SQL语句变为：`UPDATE users SET password = 'hacked' WHERE username = 'admin' OR 1=1 -- '`

### 宽字节注入（GBK/宽字符编码注入）

当数据库使用GBK、BIG5等宽字符编码时，攻击者利用转义函数（如addslashes）的漏洞，通过输入特定字符（如%df%27）将转义符号\与后续字符合并为合法宽字符，从而绕过转义。

```php
// 数据库连接使用GBK编码
$conn = new mysqli("localhost", "user", "pass", "db");
$conn->set_charset("GBK");

$id = addslashes($_GET['id']); // 转义单引号，输入 %df%27 变为 %df%5c%27
$sql = "SELECT * FROM users WHERE id = '$id'";
// 实际SQL：SELECT * FROM users WHERE id = '運''
// GBK编码中 %df%5c 被解析为 "運"，单引号逃逸！
```
攻击方式:
- 输入%df%27（URL解码为�'）：
- addslashes转义单引号为%df%5c%27。
- GBK编码中%df%5c被识别为合法字符“運”，剩余%27（单引号）逃逸，形成注入点。

## 4.常见防护绕过技巧

### 1. 关键字过滤绕过

- 大小写混淆：UnIoN SeLeCt
- 双写关键字：UNIUNIONON（若过滤逻辑为替换UNION为空）。
- 注释符分割：UN/**/ION、SEL/*!50000ECT*/（利用MySQL特性）。
- 编码混淆：十六进制、URL编码、Unicode编码（如%55%4E%49%4F%4E对应UNION）。

```php
-- 利用注释绕过
SELECT * FROM users WHERE id = 1 /*!UNION*/ SELECT 1,2,3;

-- 十六进制绕过
SELECT * FROM users WHERE name = 0x61646D696E; -- 等价于 'admin'
```
### 2. 绕过addslashes或magic_quotes_gpc

- 宽字节注入（如前文所述）。
- 数字型注入：若参数本应为数字，但未强制类型转换，可构造id=1 OR 1=1

