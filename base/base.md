# 基本理论知识

## 输入
用户在 HTML 表单中输入数据，然后通过表单提交将数据发送到 PHP 脚本进行处理。常见的表单提交方式有 GET 和 POST。
### 1. $_GET,$_POST,$REQUEST
```php
<!DOCTYPE html>
<html>
<body>
    <form action="process.php" method="get">
        <label for="name">姓名:</label>
        <input type="text" id="name" name="name">
        <input type="submit" value="提交">
    </form>
</body>
</html>
// process.php
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    echo "你输入的姓名是: ". $name;
}
```
### 2. $_COOKIE
Cookie 是存储在用户浏览器中的小段数据，用于在不同页面或不同会话之间保存信息。在 PHP 里，可以使用 $_COOKIE 超全局变量来获取 Cookie 数据。

```
// 设置 Cookie
setcookie("username", "john_doe", time() + 3600, "/");

// 获取 Cookie
if (isset($_COOKIE['username'])) {
    $username = $_COOKIE['username'];
    echo "欢迎回来, ". $username;
}
```

### 3.  $_SESSION
Session 用于在多个页面之间跟踪用户的会话状态。PHP 提供了 $_SESSION 超全局变量来管理会话数据。

```php
// 开启会话
session_start();

// 设置 Session 数据
$_SESSION['user_id'] = 1;

// 获取 Session 数据
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    echo "你的用户 ID 是: ". $user_id;
}
```

### 4. $_FILES
用户可以通过 HTML 表单上传文件到服务器，PHP 会将上传的文件信息存储在 $_FILES 超全局变量中。
```php
<!DOCTYPE html>
<html>
<body>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="fileToUpload">
        <input type="submit" value="上传文件">
    </form>
</body>
</html>
// upload.php
if ($_FILES["fileToUpload"]["error"] == 0) {
    $fileName = $_FILES["fileToUpload"]["name"];
    $tmpName = $_FILES["fileToUpload"]["tmp_name"];
    // 处理文件上传逻辑
    move_uploaded_file($tmpName, "uploads/". $fileName);
    echo "文件上传成功";
}
```

### 5. HTTP 请求头输入
HTTP 请求头包含了关于请求的额外信息，如用户代理、引用页面等。在 PHP 中，可以使用 $_SERVER 超全局变量来获取这些信息

常见的可从 $_SERVER 中获取的请求头信息及示例代码如下：
```php
// headers.php
if (isset($_SERVER['HTTP_USER_AGENT'])) {
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    echo "你的用户代理是: ". $userAgent;
}
if (isset($_SERVER['HTTP_REFERER'])) {
    $referer = $_SERVER['HTTP_REFERER'];
    echo "Referer: ". $referer;
}
```


### 6. 数据库输入
从数据库中查询数据也可以看作是一种输入方式。通过 SQL 查询语句从数据库中获取数据，然后在 PHP 中进行处理。

```php
// 连接数据库
$conn = new mysqli("localhost", "username", "password", "database");

// 检查连接是否成功
if ($conn->connect_error) {
    die("连接失败: ". $conn->connect_error);
}

// 查询数据
$sql = "SELECT name FROM users WHERE id = 1";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $name = $row['name'];
    echo "从数据库中获取的姓名是: ". $name;
}

$conn->close();
```

### 7. 外部API输入
在现代 Web 开发中，PHP 应用程序经常会与外部 API 进行交互，获取第三方服务提供的数据。可以使用 curl 或 file_get_contents 等函数来发送 HTTP 请求并获取响应数据。

#### 使用 curl 获取数据
```php
$ch = curl_init();
$url = 'https://api.example.com/data';
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Curl error: '. curl_error($ch);
}
curl_close($ch);
echo $response;
```
#### file_get_contents
```php
$url = 'https://api.example.com/data';
$response = @file_get_contents($url);
if ($response === false) {
    echo "无法获取数据";
} else {
    echo $response;
}
```

### 8. 配置文件

```php
$config = parse_ini_file('config.ini');
$host = $config['db_host'];
$user = $config['db_user'];
$password = $config['db_password'];
$dbname = $config['db_name'];
```

## PHP伪协议

### 1. file:// 协议
适用版本：几乎所有 PHP 版本都支持 file:// 协议。因为 file:// 是最基础的用于访问本地文件系统的协议，从 PHP 早期版本到最新版本都可以正常使用。例如，在 PHP 4.x、PHP 5.x、PHP 7.x 以及 PHP 8.x 等各个版本中，像 file_get_contents、fopen 等文件操作函数都能通过 file:// 协议访问本地文件。

### 2. php:// 协议
php://input
适用版本：从 PHP 4.3.0 开始支持 php://input。在这个版本之后，开发者可以使用 php://input 来读取 POST 请求的原始数据。不过，在 PHP 5.6.0 之前，php://input 不能用于 enctype="multipart/form-data" 的 POST 请求。
php://filter
适用版本：从 PHP 5.0.0 开始引入 php://filter 协议。这个协议提供了对文件内容进行过滤和转换的功能，在后续的 PHP 版本（如 PHP 5.x、PHP 7.x 和 PHP 8.x）中都得到了持续支持和完善。

```
http://example.com/vulnerable.php?file=php://filter/read=convert.base64-encode/resource=index.php
```

### 3. data:// 协议
适用版本：从 PHP 5.2.0 开始支持 data:// 协议。在这个版本之后，开发者可以在 URL 中直接包含数据，并且可以指定数据的 MIME 类型和编码方式。该协议在后续的 PHP 版本中也一直被支持。

```
http://example.com/vulnerable.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8%2b
```

### 4. zip:// 协议
适用版本：从 PHP 5.2.0 开始支持 zip:// 协议。此版本之后，开发者可以使用 zip:// 协议来访问 ZIP 压缩文件中的文件。只要安装了相应的 ZIP 扩展（通常是默认安装的），在 PHP 5.x、PHP 7.x 和 PHP 8.x 等版本中都能正常使用。
需要注意的是，虽然这些伪协议在指定版本之后基本都能正常使用，但随着 PHP 版本的更新，一些安全机制和配置选项可能会影响伪协议的使用效果。例如，在较新的 PHP 版本中，可能会默认开启更严格的安全设置，限制某些伪协议的使用或对其进行更严格的过滤。