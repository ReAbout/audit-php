# PHP 调试环境搭建

Xdebug 是一个 PHP 的调试扩展，允许开发者通过 IDE（如 PhpStorm）进行远程调试。

- 客户端（IDE）：开发者使用 IDE（如 PhpStorm）设置断点并启动调试会话。
- 服务器（PHP 应用）：PHP 应用运行在服务器上，Xdebug 扩展已安装并启用。
- 通信：当 PHP 应用执行到断点时，Xdebug 会通过 HTTP 或 DBGP 协议与 IDE 通信，发送调试信息（如变量值、调用栈等）。
- 交互：开发者可以在 IDE 中查看和修改变量、单步执行代码等。

>xdebug调试通信逻辑，是web容器主动去找idea之类客户端建立连接，所以一定要保证服务器到客户端可访问性。

## 0x01 服务侧安装配置

#### Docker远程调试
各类官方版本的PHP镜像，php:5.6-apache，php:7.2-apache等
```
docker run -d -p 9991:80 -v /home/re/www/html:/var/www/html php:5.6-apache
```
进入容器安装xdebug和mysqli
```
docker-php-ext-install mysqli \
&& pecl install xdebug \
&& docker-php-ext-enable xdebug
```
低版本的兼容性有问题，需要指定版本
```
docker-php-ext-install mysqli \
&& docker-php-ext-install mysql \
&& pecl install xdebug-2.5.0
```

后续修改xdebug配置信息。    
其中IDE配置地址可设置为 host.docker.internal 为宿主机域名。   

### Linux远程调试
#### （1）环境
Ubuntu16.04虚拟机 + Xdebug
#### （2） Install on ubuntu
- 首先安装好 Apache,Mysql,php   -
```
sudo apt install apache2 php  libapache2-mod-php mysql-server
```
- xdebug install
```
sudo apt-get install php-xdebug
```
- 可以查看是否安装成功：   
```
php -m
```
- `/etc/php/7.0/apache2/php.ini`添加如下配置：   
```
xdebug.remote_enable = 1
xdebug.remote_autostart = 1
```
- 一切配置好了，记得好重启apache2 服务。

#### （3） 使用
虚拟机开放ssh   
通过 ssh target方式连接虚拟机，就可以进行远程调试了。   

### Windows远程调试
### （1）环境
Windows系统 + Xdebug
### （2）Install on windows
可以直接找对应的php版本的xdebug，都是编译好的。    
https://xdebug.org/download/historical     
配置php.ini，详情见xdebug配置

## 0x02 客户端工具配置

#### VSCode
- 安装 php debug 插件   
- 创建默认php调试配置   

#### phpstrom(idea)

1. 启用 Xdebug:
打开 PhpStorm，进入 File > Settings > PHP > Debug。
在 Xdebug 部分，确保 Debug port 设置为 9003。

2. 配置服务器:
进入 File > Settings > PHP > Servers。
点击 + 添加新服务器，填写 Name 和 Host。
勾选 Use path mappings，并映射项目目录到服务器路径。

>注意一定要配置路径映射，要不会找不到相应的文件调试。



## 0x03 xdebug配置
> xdebug 2.X 和 xdebug 3.X 的php.ini配置文件不同

### xdebug 2.X 配置
```
[xdebug] 
zend_extension="/usr/local/lib/xdebug.so" 
xdebug.remote_autostart=1 
xdebug.remote_enable=1
;客户端ip,IDE 所在机器的 IP
xdebug.remote_host = "192.168.117.1" 
xdebug.idekey="PHPSTORM" 
xdebug.remote_handler=dbgp 
xdebug.remote_port=9000
```
### xdebug 3.X 配置
```
[xdebug] 
zend_extension="/usr/local/lib/xdebug.so" 
xdebug.mode=debug 
xdebug.discover_client_host=true 
xdebug.client_port=9000
;客户端ip
xdebug.client_host="192.168.117.1" 
xdebug.idekey="PHPSTORM" 
xdebug.log=/tmp/xdebug.log
xdebug.start_with_request=yes
```


## 0x04 php报错开启

### php单文件： 
```
ini_set("display_errors", "On");
error_reporting(E_ALL | E_STRICT)
```
### 修改php.ini：
```
display_errors = On
error_reporting  =  E_ALL & ~E_NOTICE

```
