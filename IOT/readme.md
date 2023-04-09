## IoT漏洞Top 10-Payatu

### P1. 硬编码的敏感信息

开发人员在程序中对静态数据进行硬编码是在开发过程中对信息进行硬编码的常见做法。但是，当敏感信息被硬编码时，就会出现问题。很有可能在固件以及移动应用程序或胖客户端中对敏感信息进行了硬编码。问题在于，该产品的所有实例均保持相同，并且可用于攻击现场部署的任何产品实例。一些经过硬编码的敏感信息的示例：

凭证，如设备服务，云服务等
加密密钥，如私钥，对称加密密钥
证书，客户端证书等
API密钥，如外部对接API、私有API
URL，开发，固件相关，用户相关，后端等
配置文件

### P2. 启用的硬件调试端口

设备硬件可能已打开调试端口以与系统交互。简而言之，它是PCB上的一组引脚，它们连接到微控制器/微处理器引脚，您可以使用客户端软件连接到这些引脚，以通过硬件通信协议进行通信，从而使您可以与系统交互。交互和特权的级别取决于协议的类型及其用法。例如，可能有UART接口的管脚输出，它可以使您访问高级软件/应用程序，即命令外壳，记录器输出等。您还可以使用以下协议与微控制器进行低级交互： JTAG，SWD等，这些可让您直接控制微控制器，因此您可以测试和分析微控制器的引脚值，读/写内部闪存，读/写寄存器值，调试OS /基本固件代码等等。如果在设备上启用了这些端口/引脚，则攻击者可以劫持设备和/或从设备中提取敏感信息，包括固件和数据。通常启用这些端口以解决生产设备中的故障/调试问题。

### P3. 不安全的固件

这里的术语“不安全”是指固件的管理方式，而不是固件本身的代码漏洞。固件包含设备的业务逻辑，并且大多是专有的，即供应商的IP（知识产权）。如果攻击者可以访问纯文本固件，则他/她可以对其进行反向工程以发现安全问题或克隆逻辑并最终克隆产品本身。漏洞取决于在设备上存储和更新固件的方式。如果不小心对存储或移动中的固件进行适当加密（更新），则攻击者可以控制它。固件的一些问题是（但不限于）：

固件以纯文本格式存储在内存芯片上
固件未签名，并且/或者引导程序未在加载之前验证固件的完整性。
固件更新以纯文本格式从云或移动设备传输到设备。
固件更新通过明文通信协议（例如HTTP）进行传输。
对所有设备实例使用单个对称密钥加密的固件。
固件加密密钥与更新一起传输到设备。
正确实施的基于PKI的系统可以确保最佳安全性，但是大多数低功耗传感器缺乏有效实施PKI的计算能力。同样，如果更新是安全的，但是可以使用其他漏洞从设备中提取密钥，那么整个练习将是徒劳的。

### P4. 不安全的数据存储

该问题在设备和移动应用程序中都很突出。在设备硬件中更明显，可能是由于假设反转硬件很困难。敏感数据（如果未安全存储）可能会被攻击者提取并利用来破坏系统。除了安全问题，如果用户的个人数据没有得到适当的保护，它也可能会涉及隐私。一些常见问题：

敏感数据以明文形式存储在内存芯片上；
敏感数据已加密存储，但可以访问加密密钥；
自定义加密用于加密数据；
无访问控制权，无法修改数据；
移动设备上的数据存储不安全。应用程序（请参阅“ P9。不安全的移动界面”）

### P5. 认证不足

设备可能会使用不正确的身份验证机制或不使用身份验证机制，如果身份验证机制实施得不好，则攻击者将完全绕过身份验证机制，并向设备发送未经授权的命令。对于关键的物联网设备而言，这是一个严重的问题，因为网络上的任何人（TCP / IP或无线电）都可以覆盖正常操作并控制设备。设备上发生的一些身份验证问题包括（但不限于）：

无客户端身份验证
通过明文通信通道进行身份验证
用于凭据的加密不正确
可预测的凭据
默认凭据

### P6. 不安全的沟通

如果攻击者能够嗅探，分析，重播和提取通信中的敏感信息，则物联网生态系统中的通信可能不安全。该漏洞可能是由于使用不安全的通信协议或协议缺陷本身引起的。为了简单起见，供应商可能选择使用不安全的通信方式。由于IoT是一项新兴技术，因此许多IoT协议没有定义适当的安全机制，或者供应商实施默认的不安全模式。问题包括（但不限于）：

共享敏感信息时未加密的通信
使用自定义加密
使用自定义/专有协议
使用的加密不正确
使用协议默认（弱）安全模式
使用已知问题的协议
重播问题

### P7. 不安全的配置

当设备配置不安全或设备不允许用户修改配置参数时，会发生此问题。移动应用程序和云配置中也会发生此问题。为了使事情简单或快速交付产品，开发人员可能选择使用简单但不安全的配置和/或不允许更改。一些明显的问题是（但不限于）：

使用默认的不安全配置
禁止集成商和/或用户修改配置
版本产品中的低级协议和硬件配置不安全
加密模式和设置不安全
对共享或存储的用户个人数据了解甚少或根本看不到

### P8. 数据输入过滤不足

随着越来越多的物联网协议在物联网生态系统中实现，这将成为一个重大问题。例如，来自设备的遥测数据可能会被云或IoT网关信任，从而导致已知和未知的安全问题，例如远程代码执行，基于Web的攻击（例如SQL注入），跨站点脚本编写等等。我们希望这一点将来会优先发展。尽管成熟的实现确实可以过滤传统技术的数据，但对于新的物联网协议实现来说，同样有待提高。

### P9. 移动接口不安全

从安全的角度来看，与传感器技术相比，移动技术已经成熟，因此我们将所有移动安全问题归为一类。这并不意味着它们的优先级较低，因为您可以看到某些高优先级漏洞也适用于移动设备。但是，由于技术的成熟，它已经具有关于安全性问题和安全实现的大量信息。作为OWASP的粉丝，我们建议从OWASP Mobile十大漏洞开始，这些漏洞将解决大多数安全问题。

### P10. 不安全的云/ Web界面

如“ P9。不安全的移动界面”，同样适用于云和网络。如果设备具有Web界面，您仍然可以通过Web攻击来拥有该设备，但是这些安全问题已经得到很好的定义和理解。同样，我们建议从OWASP Web十大漏洞开始，以了解和缓解Web安全问题以及来自Cloud Security Alliance的云安全文档。请注意，这不是唯一可用的知识库，并且应该查看互联网上可用的工具和研究论文。重要的是要注意，云构成了物联网生态系统的数据存储和通信主干。如果云遭到破坏，则可能导致整个IoT生态系统遭到破坏，包括全球和整个宇宙中所有已部署的产品。

## IoT测试工具

file

dexdump

string

### IDA

反编译软件

### Ghidra

商业反编译软件

### binwalk

对固件进行扫描

```
binwalk firmware.bin

binwalk firmware.bin | head
```

检查固件是否加密可直接扫描

未加密的扫描结果

```
$ binwalk GS108Tv3_GS110TPv3_GS110TPP_V7.0.6.3.bix 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
64            0x40            LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, uncompressed size: -1 bytes
```

加密后的扫描结果

```
$ binwalk DIR3040A1_FW113B03.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

通过查看固件的熵值也可以判断是否加密或压缩。熵值是用来衡量不确定性，熵值越大则说明固件越有可能被加密或者压缩了。这个地方说的是被加密或者压缩了，被压缩的情况也是会让熵值变高或者接近1的，如下是使用 `binwalk -E` 查看一个未加密固件（RAX200）和加密固件（DIR 3040）。可以看到，RAX200和DIR 3040相对比，不像后者那样直接全部是接近1了。

提取文件

```
binwalk -e firmware.bin
```

递归提取文件

```
binwalk -Me firmware.bin
```

指定文本搜索

```
binwalk –y filename firmware.bin
```

排除文本搜索

```
binwalk –x filename firmware.bin
```

固件比较，比较结果中相同字节绿色显示，不同字节红色显示，蓝色表示一些文件中的不同部分

```
binwalk –W firmware1.bin firmware2.bin firmware3.bin
```

从文件中过滤HTML等文件

```
$ find . -name "*htm*" | grep -i "firmware"
./etc_ro/lighttpd/www/web/MobileUpdateFirmware.html
```

参考文档：https://paper.seebug.org/1651/

#### 安装教程

提示：Kali环境安装很简单，建议在Kali环境安装

下载软件包后https://github.com/ReFirmLabs/binwalk/releases解压到随意目录，Python运行安装文件

```
python setup.py install
```

出现如下字样即安装完成

```
Processing dependencies for binwalk==2.3.3
Finished processing dependencies for binwalk==2.3.3
```

安装完成后可直接在控制台中使用binwalk命令

参考：https://github.com/ReFirmLabs/binwalk/wiki/Quick-Start-Guide

#### 命令详解

https://cloud.tencent.com/developer/article/1515285

### MQTTX

MQTT连接工具
下载地址：https://mqttx.app/

## MQTT

MQTT基于TCP协议默认端口为1883，主要功能就两个，发布Publish和订阅Subscribe。关于MQTT的攻击面，主要可以考虑MITM、口令问题、权限问题
1.MIMT

2.口令问题

MQTT安全测试

https://www.modb.pro/db/230215

[mosquitto基于SSL/TLS安全认证测试MQTT - 走看看](http://t.zoukankan.com/airb-p-13229419.html)

[GitHub - eclipse/mosquitto: Eclipse Mosquitto - An open source MQTT broker](https://github.com/eclipse/mosquitto)

[物联网安全之MQTT协议安全 - 安全客，安全资讯平台](https://www.anquanke.com/post/id/212335)

[MQTT安全初探 - SecPulse.COM | 安全脉搏](https://www.secpulse.com/archives/160231.html)

MQTT爆破

[MQTT安全初探 - SecPulse.COM | 安全脉搏](https://www.secpulse.com/archives/160231.html)
MQTT查看所有Topic说明
https://wenku.baidu.com/view/8f9209153a68011ca300a6c30c2259010202f39b.html

3.权限问题

2、固件

### Mosquitto

#### Docker部署步骤

拉取镜像

```
docker pull eclipse-mosquitto
```

启动服务

```
docker run -it --name=mosquitto -p 1883:1883 -d eclipse-mosquitto
```

进入容器修改配置

```
docker exec -it mosquitto sh
vi /mosquitto/config/mosquitto.conf
```

增加监听 `listener 1883`

关闭匿名登录 `allow_anonymous false`

指定账号密码文件 `password_file /mosquitto/config/pwdfile.conf`

配置完成后保存后退出

在 `/mosquitto/config/` 路径下创建文件 `touch pwdfile.conf`

使用mosquitto_passwd命令创建账号和密码

```
mosquitto_passwd -b pwdfile.conf admin password
```

退出容器后重启服务

```
docker restart mosquitto
```

### 参考

简单部署 https://blog.csdn.net/weixin_42534563/article/details/124252477

持久化部署 https://www.hangge.com/blog/cache/detail_2896.html

对MQTT进行模糊测试 https://www.modb.pro/db/230215

[浅析MQTT安全](http://rui0.cn/archives/975)

## Bluetooth

蓝牙漏洞检查

https://www.antiy.com/response/blueborne/blueborne.pdf

近期蓝牙漏洞
https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/reporting-security/

CVE-2021-28139
它允许远程攻击者通过蓝牙 LMP 数据包，在易受攻击的设备上运行自己的恶意代码。
检查蓝牙固件版本

## IoT通用检查点

| 检查项目         | 方法  |     |
| ------------ | --- | --- |
| MQTT口令检查     |     |     |
| MQTT安全传输     |     |     |
| MQTT服务端匿名访问  |     |     |
| MQTT公开暴露漏洞   |     |     |
| 数据传输协议请求重放风险 |     |     |
| 蓝牙漏洞检测       |     |     |

## 参考链接

IoT安全测试南

https://cloud.tencent.com/developer/article/1697299

[RFID PN532修改NFC卡余额](https://blog.csdn.net/TymonPaul/article/details/80425617)

工具清单

https://zhuanlan.zhihu.com/p/50388015

物联网IoT自动化渗透测试

https://www.pianshen.com/article/26871109392/

[物联网安全从入门到入坑](https://paper.seebug.org/1045/)

[IoT安全系列-如何发现攻击面并进行测试](https://www.anquanke.com/post/id/84762)

[加密固件之依据老固件进行解密](https://paper.seebug.org/1651/)

[D-Link DIR 3040 从信息泄露到 RCE](https://paper.seebug.org/1650/)

IoT安全测试入门

https://www.bilibili.com/video/av977289646

https://www.bugbank.cn/live/

https://www.kanxue.com/

IoT固件提取思路

https://bbs.pediy.com/thread-230095.htm
