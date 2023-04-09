# Web测试全流程归纳总结

## 信息收集

### 域名注册信息

#### Whois

站长之家
https://whois.chinaz.com/

万网
https://whois.aliyun.com/

#### 解析域名

解析目标域名/主机名的IP地址

```bash
dig +short example.com
```

获取域名的详细解析过程：

```bash
dig +trace example.com
```

### 验证是否存在CDN或WAF

#### 方法1.多地去Ping

| 在线多地Ping网站              |
| ----------------------- |
| http://ping.chinaz.com/ |
| http://ping.aizhan.com/ |
| http://ce.cloud.360.cn/ |

#### 方法2.NSLOOKUP

```bash
nslookup example.com
```

#### 方法3.直接用在线工具查看CDN

http://www.cdnplanet.com/tools/cdnfinder

http://www.ipip.net/ip.html

### 绕过CDN和WAF查看真实IP

#### 方法1.通过域名查询站点查询历史IP

| DNS历史记录与子域名类站点                     | 说明                                    |
| ---------------------------------- | ------------------------------------- |
| https://iphostinfo.com/            | 可以查出几年内网站用过的IP、机房信息，遍历FTP、MX记录和常见二级域名 |
| https://dnsdb.io/zh-cn/            | 偶尔服务器不可用                              |
| https://x.threatbook.cn/           | 需要登录，有查询次数限制                          |
| https://censys.io/ipv4?q=baidu.com | 速度较慢，需要翻墙                             |
| https://viewdns.info/              | 能分析内链之类找出可能的IP地址，此外还会记录历史             |
| https://site.ip138.com/            | 速度比较快                                 |
| https://securitytrails.com/        | 没那么准确，但是可以查子域名                        |

#### 方法2.对方服务器给自己发邮件暴露IP

邮箱服务也在主机上，泄露了真实的IP

#### 方法3.APP客户端爆IP

### 查询子域名

注意：有些站长只给主站或流量大的子域名做了CDN，而很多子域名都是和主站在同一台服务器上或处于一个段，可以通过子域名来辅助找到网站真实IP

##### 扫描工具主动扫描

| 工具名称或地址             | 说明                  |
| ------------------- | ------------------- |
| layer子域名挖掘机         | 客户端，推荐虚拟机部署，字典要自己丰富 |
| https://tools.yum6.cn/Tools/urlblast/         | 一个在线的简单子域名扫描网站 |
| http://z.zcjun.com/ | 在线子域名挖掘，不太好用        |
| fuzzdomain          | 客户端，很好用，速度快         |

##### 搜索引擎类工具扫描

1.搜索引擎拿子域名

可用搜索引擎语法查询子域名：谷歌、百度、bing、搜狗(搜索微信文章)、雅虎等略有差异

| 示例                  | 说明                                |
| ------------------- | --------------------------------- |
| site:=主域名           | 搜索其主要域名下面的子域名                     |
| allintext:=搜索文本     | 不包括网页标题和链接                        |
| allinlinks:=搜索链接    | 不包括文本和标题                          |
| related:URL=DemoURL | 列出于目标URL地址有关的网页                   |
| link:URL=DemoURL    | 列出到链接到目标URL的网页清单                  |
| 使用“-”去掉不想看的结果       | 例如site:baidu.com -image.baidu.com |

百度语法参考链接

https://www.cnblogs.com/k0xx/p/12794452.html

谷歌Google Hack语法

https://blog.csdn.net/u012991692/article/details/82937100?spm=1001.2014.3001.5501
![](https://www.miacraft.cn/public/2021/03/20181004133738125.png)

Google Hack Database

此站点翻墙比较快
https://www.exploit-db.com/google-hacking-database

### 资产收集站点

通过旁站，同C段，特征收集相应信息

| 站点                                         | 说明                                  |
| ------------------------------------------ | ----------------------------------- |
| https://fofa.so/                           | 根据域名定位出IP，包括子域名等，比较好用               |
| https://www.shodan.io                      | 资产相关或特征值关键字定位出IP                    |
| https://www.zoomeye.org/                   | 根据域名定位IP等资源，知道创宇旗下的资产收集站点           |
| https://www.yunsee.cn/                     | 云悉在线资产平台，需要登录及收费                    |
| https://www.virustotal.com/gui/home/search | 通过域名查询IP以及历史解析，子域名等信息，很好用           |
| https://dnsdumpster.com/                   | 根据域名查询IP及其子域名及其IP分布等                |
| https://duckduckgo.com/                    | 不会存储你个人信息的搜索引擎，搜索结果类似普通搜索引擎(访问需要翻墙) |
| https://icp.aizhan.com/                    | 域名备案查询，仅适用于国内正规站点                   |
| https://crt.sh/                            | SSL证书信息查询                           |
| http://subdomain.chaxun.la                 | 查询啦(站点已关闭，不知道后面会不会开起来)              |

### DNS信息查询

DNS信息查询的目的通过域名查询注册者、邮箱、手机号、座机号、ASN号等信息

| 站点地址                              | 说明                    |
| --------------------------------- | --------------------- |
| https://dnsdumpster.com/          |                       |
| https://www.dnsdb.io              | DNS搜索引擎               |
| https://searchdns.netcraft.com/   | 访问较慢，结果不太准确           |
| http://whois.nawang.cn/           |                       |
| https://whois.aliyun.com/         |                       |
| https://whois.west.cn/            |                       |
| http://whois.chinaz.com/          | 站长之家                  |
| https://www.tianyancha.com        | 天眼查                   |
| http://www.gsxt.gov.cn/index.html | 国家企业信用信息系统，主要根据企业名称查询 |
| https://beian.miit.gov.cn/        | ICP备案查询，境内非常有用        |

### 域传送漏洞检测

域传送是一种DNS事务，用于在主从服务器间复制DNS记录。虽然如今已经很少见主机会开启，但是还是应该确认一下。一旦存在域传送漏洞，就意味着你获取了整个域下面所有的记录

```bash
dnsrecon -d example.com
dnsenum example.com
```

### 业务相关

#### Github泄露

| 搜索格式示例                   | 说明                        |
|:------------------------ | ------------------------- |
| in:name test             | 仓库标题搜索含有关键字               |
| in:descripton test       | 仓库描述搜索含有关键字               |
| in:readme tes            | Readme文件搜素含有关键字           |
| stars:>3000 test         | stars数量大于3000的搜索关键字       |
| stars:1000..3000 test    | stars数量大于1000小于3000的搜索关键字 |
| forks:>1000 test         | forks数量大于1000的搜索关键字       |
| forks:1000..3000 test    | forks数量大于1000小于3000的搜索关键字 |
| size:>=5000 test         | 指定仓库大于5000k(5M)的搜索关键字     |
| pushed:>2019-02-12 test  | 发布时间大于 2019-02-12的搜索关键字   |
| created:>2019-02-12 test | 创建时间大于2019-02-12的搜索关键字    |
| user:test                | 用户名搜素                     |
| license:apache-2.0 test  | 明确仓库的LICENSE搜索关键字         |
| language:java test       | 在Java语言的代码中搜索关键字          |
| user:test in:name test   | 组合搜索,用户名test的标题含有test的    |

#### 网盘泄露

网盘搜索

http://magnet.chongbuluo.com/

敏感路径扫描

https://github.com/ring04h/weakfilescan

## 公开情报收集 OSINT

### 社会工程学技巧

#### REG007找注册过的网站

根据邮箱和手机号查询注册的网站(需要有注册邀请码)

https://www.reg007.com/

通过注册的账号平台去搜寻更多信息

#### 特定网站找寻账号

1.通过找回密码，如果可以进入下一步则证明账号存在

2.通过登录，输入出现单单“密码错误”则证明账号存在

3.注册时，判断用户名是否能使用

#### 社交信息扩展

通过QQ邮箱、163邮箱等搜索支付宝、淘宝、新浪微博、微信账号

查看QQ空间：相册、地区、星座、生日、昵称、手机号等信息

查看QQ说说：留言、日志的好友，加好友钓鱼

发布时间线与终端，可根据客户端制定渗透策略

注意链接、图片、视频链接可能包含用户ID

图片中的EXIF可能会有GPS定位和手机类型，图片内容特征

视频也有可能有水印、社交账号ID、拍摄地点

#### 手机号信息扩展

搜索QQ、微信、微博、钉钉、支付宝、淘宝

#### 获取公司和子公司信息

通过[企查查](https://www.qcc.com/)、[天眼查](https://www.tianyancha.com/)、[爱企查](https://aiqicha.baidu.com/)

#### 企业架构以及关键员工信息

小程序、微信公众号、App、微博、邮箱、生活号、领英、脉脉、飞书

#### 搜索过滤信息

在微博、Instgram、Twitter、Facebook、百度贴吧搜索相近关键字，按地域、年龄、性别、用户名等筛选

#### 被动钓鱼操作

钓鱼邮件、钓鱼网站、木马及恶意程序

综合利用信息生成密码字典

### 搜索引擎 OSINT

Hacking搜索常用语法

| 格式           | 说明                             |
| ------------ | ------------------------------ |
| intext       | 把网页中的正文内容中的某个字符作为搜索的条件，仅Google |
| intitle      | 把网页标题中的某个字符作为搜索的条件             |
| cache        | 搜索搜索引擎里关于某些内容的缓存               |
| filetype/ext | 指定一个格式类型的文件作为搜索对象              |
| inurl        | 搜索包含指定字符的URL                   |
| site         | 在指定的(域名)站点搜索相关内容               |

Hacking其他语法

| 格式   | 说明                                          |
| ---- | ------------------------------------------- |
| ""   | 把关键字打上引号，整体搜索                               |
| or   | 同时搜索两个或更多关键字                                |
| link | 搜索某个网站的链接 link:baidu.com即返回所有和baidu做了链接的URL |
| info | 查找指定站点的一些基本信息                               |

常用搜索示例

后台地址

```
site:target.com intext:管理 | 后台 | 后台管理 | 登陆 | 登录 | 用户名 | 密码 | 系统 | 账号 | login | system
site:target.com inurl:login | inurl:admin | inurl:manage | inurl:manager | inurl:admin_login | inurl:system | inurl:backend
site:target.com intitle:管理 | 后台 | 后台管理 | 登陆 | 登录
```

上传类漏洞地址

```
site:target.com inurl:file
site:target.com inurl:upload
```

注入页面(批量注入工具结合搜索引擎)

```
site:target.com inurl:php?id=
```

编辑器页面

```
site:target.com inurl:ewebeditor
```

目录遍历漏洞

```
site:target.com intitle:index.of
```

SQL错误

```
site:target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:”Warning: mysql_query()" | intext:”Warning: pg_connect()"
```

phpinfo()

```
site:target.com ext:php intitle:phpinfo "published by the PHP Group"
```

配置文件泄露

```
site:target.com ext:.xml | .conf | .cnf | .reg | .inf | .rdp | .cfg | .txt | .ora | .ini
```

数据库文件泄露

```
site:target.com ext:.sql | .dbf | .mdb | .db
```

日志文件泄露

```
site:target.com ext:.log
```

备份和历史文件

```
site:target.com ext:.bkf | .bkp | .old | .backup | .bak | .swp | .rar | .txt | .zip | .7z | .sql | .tar.gz | .tgz | .tar
```

公开文件泄露

```
site:target.com filetype:.doc | .docx | .xls | .xlsx | .ppt | .pptx | .odt | .pdf | .rtf | .sxw | .psw | .csv
```

邮箱信息

```
site:target.com intext:@target.com
site:target.com 邮件
site:target.com email
```

社会工程学信息

```
site:target.com intitle:账号 | 密码 | 工号 | 学号 | 身份证
```

### 信息收集工具

| 名称             | 说明                                |
| -------------- | --------------------------------- |
| Wappalyzer     | 识别网站使用的中间件及其版本，再去漏洞库和搜索引擎找公开披露的漏洞 |
| Shodan         | 被动信息收集工具，识别开放端口，主机服务等             |
|                |                                   |
| Firefox渗透测试便携版 | 工具集成很多                            |
|                |                                   |
|                |                                   |

信息调研

请求逻辑路线

是否有CDN、是否有WAF、是否有网关、是否有全局负载均衡（如GTM）、是否有负载均衡

开发框架

如Spring Cloud

资产清单

子域名

URI接口清单

### 漏洞库信息平台

乌云库\乌云镜像\GHDB\CNVD\CVE等公开漏洞库

### 浏览器插件

#### Wappalyzer

识别网站使用的中间件及其版本，再去漏洞库和搜索引擎找公开披露的漏洞

#### HackTools

综合插件,很强大

https://github.com/LasCC/Hack-Tools

#### 星维

Chrome插件，根据IP定位IOC威胁情报

#### SwitchOmega

代理切换插件



### 参考链接

信息收集思路&工具分享

https://mp.weixin.qq.com/s/N16Z0igvIYFIiUfve5QfhA



## 漏洞扫描

### [Nikto Web服务漏洞扫描器](https://github.com/coltisa/security_collection#nikto)

AWVS

Netsparker

AppScan

XRAY

Nuclei

针对性扫描

Log4j

[GitHub - fullhunt/log4j-scan: A fully automated, accurate, and extensive scanner for finding log4j RCE CVE-2021-44228](https://github.com/fullhunt/log4j-scan)

WebLogic

https://github.com/0xn0ne/weblogicScanner

## 逻辑检查

创建两个A和B账号，分别获取登录后的Token、用户ID、用户昵称等信息

- [ ] Case 1

```
只带用户ID，空的Token或者假Token请求接口
```

- [ ] Case 2

```
用A的Token带上B的用户ID请求接口
```

- [ ] Case 3

```
公共信息发送接口阈值限制检查，如邮件验证码发送接口、短信发送接口
```

- [ ] Case 4

```
对验证码（短信\邮箱）的失效周期检查
```

- [ ] Case 5

```
对验证码（短信\邮箱）的混用检查，低风险级别验证码用于校验敏感操作
```

- [ ] Case 6

```
Token失效周期检查，包括登录Token、验证码Token、修改密码等Token
```

- [ ] Case 7 重置密码

```
1.重置一个账户，不发送验证码，设置验证码为空发送请求。
2.发送验证码，查看相应包
3.验证码生存期的爆破
4.修改相应包为成功的相应包
5.手工直接跳转到校验成功的界面
6.两个账户，重置别人密码时，替换验证码为自己正确的验证码
7.重置别人密码时，替换为自己的手机号
8.重置自己的成功时，同意浏览器重置别人的，不发验证码
9.替换用户名，ID，Cookie，Token参数等验证身份的参数
10.通过越权修改他人的找回信息如手机/邮箱来重置
```

图片后台地址\图片后面的信息

跳转参数\奇怪的参数

泄露邮箱等社工信息

用户名爆破检查

用户密码逻辑检查

密码验证问题检查

逻辑检查与Fuzz参考

https://www.freebuf.com/vuls/221129.html



## 测试路线

### 半自动代理链扫描

1.BurpSuite+BurpSuite扫描插件+XRAY

AWVS+XRAY

2.BurpSuite+Nuclei扫描插件

### 自动化扫描

Crawlergo+XRAY

Netsparker

业务逻辑检查

OWASP Checklist

SQL Injection

Burp Suite与SQLMap的联动

## 参考链接

https://mp.weixin.qq.com/s/arl3mxwOONDOIeWNgfnG9Q

https://www.shentoushi.top/knowledge

应急相应笔记

https://bypass007.github.io/Emergency-Response-Notes/

[Web安全技术社区 - 网安](https://www.wangan.com/discuss/web)
