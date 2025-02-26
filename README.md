# PHP代码审计手册

【声明】个人的快速查询手册，经验整理，仅供参考。   
【内容】本手册主要关注于PHP漏洞挖掘而非利用，漏洞利用在[WEB 安全手册](https://github.com/ReAbout/web-sec)有总结。复现案例分析也是关注漏洞原理，通过调试分析加强对漏洞产生模式理解，辅助漏洞挖掘。

## 0x00 环境准备篇

- [PHP调试环境的搭建](./base/debug.md)

## 0x01 基础知识篇
- [基本理论知识](./base/base.md)
- [PHP特性中安全风险](./base/feature.md)

## 0x02 漏洞挖掘篇

### 1. 注入
- [命令注入&代码注入](./vuln/ci.md)
- [SQL注入](./vuln/sqlin.md)
- [xxe](./vuln/xxe.md)

### 2. 反序列化
- [反序列化](https://github.com/ReAbout/web-sec/blob/master/exp/EXP-PHP-Unserialize.md)

### 3. 不安全的文件操作
- [不安全文件包含](./vuln/include.md)
- [不安全的文件上传](./vuln/upload.md)

### 4. 其它安全问题
-[变量覆盖的安全问题](./vuln/var.md)


### 基于框架应用

- [基于Thinkphp应用漏洞挖掘](./framework/thinkphp.md)