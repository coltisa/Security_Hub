## 工具和测试架构说明

## 检查点

说明：以下检查点编号没有按序排列，保留各个参考文档原始编号以便定位。

参考：OWASP Mobile Security Testing Guide

### Android安全测试检查点

#### 注入缺陷（MSTG-ARCH-2 和 MSTG-PLATFORT-2）

说明：对本地文件包括SQLite、XML、Content Provider SQL注入风险进行检查
检测：检查是否存在SQLite调用、存在导出的Content Provider组件，有则判断SQL语句中是否有未校验的输入值
参考：https://blog.csdn.net/qq_35993502/article/details/120927086

#### 敏感数据之本地存储测试 (MSTG)

检测是否有敏感数据存储在本地，如用户凭据或加密密钥，包括如下的项目检查： 

SQLite敏感数据检查
说明：SQLite本地数据库可能通过加密过未加密方式存储数据
检测：通过搜索代码关键词` android.database.sqlite`检查是否使用SQLite，通过以下代码示例引用notSoSecure创建了非加密数据库，路径为/data/data/package_name/databases/privateNotSoSecure

```
SQLiteDatabase notSoSecure = openOrCreateDatabase("privateNotSoSecure",MODE_PRIVATE,null);
```

通过以下代码示例引用secureDB创建了加密数据库

```
SQLiteDatabase secureDB = SQLiteDatabase.openOrCreateDatabase(database, "password", null);
```

SD卡数据被第三方程序访问
说明：发现调用getExternalStorageDirectory，存储内容到SD卡可以被任意程序访问，存在安全隐患
检测：通过反编译或检查源代码，检查getExternalStorageDirectory相关配置参数
建议：建议存储敏感信息到程序私有目录，并对敏感数据加密

全局文件可读可写
说明：openFileOutput(String name,int mode)方法创建内部文件时，将文件设置了全局的可读写权限MODE_WORLD_READABLE或MODE_WORLD_WRITEABLE
危害：攻击者恶意写文件内容或者，破坏App的完整性，或者是攻击者恶意读取文件内容，获取敏感信息
建议：请开发者确认该文件是否存储敏感数据，如存在相关数据，请去掉文件全局可写、写属性

通过getSharedPreferences配置文件可读可写 
说明：使用getSharedPreferences打开文件时，将第二个参数设置为MODE_WORLD_READABLE 或 MODE_WORLD_WRITEABLE
危害：当前文件可以被其他应用读取和写入，导致信息泄漏、文件内容被篡改，影响应用程序的正常运行或更严重的问题
建议：使用getSharedPreferences时第二个参数设置为MODE_PRIVATE禁止使用MODE_WORLD_READABLE | MODE_WORLD_WRITEABLE模式

#### 敏感数据之日志测试 (MSTG)

说明：日志可能通过实时输出和存储到日志文件。实时数日志可以通过Logcat进行日志过滤检查，如果已经知道了应用程序的 PID，可以使用--pid 标志直接给出。日志文件需要和开发人员进一步确认是否有日志目录。

检测：如果知道PID可以直接通过PID进行过滤 `adb logcat --pid app_pid` 或者进入到Shell之后通过应用名称过滤

```
adb shell
logcat | grep app_name
```

建议：不将敏感信息通过日志输出

#### 判断敏感数据是否发送给第三方(MSTG)

说明：嵌入的第三方服务可以实现跟踪服务，监视用户行为，销售横幅广 告，改善用户体验等。 但是不能确切地知道第三方库执行的是什么代码。因此需要确保只将必要的、不敏感的信息发送到第三方。
静态检测：检查 AndroidManifest.xml 中的权限，必要时检查第三方SDK源代码。
动态检测：使用BurpSuite等工具进行抓包分析。
建议：所有发送到第三方服务的数据都应该匿名化。可以追踪到用户账户或会话的数据都不应该发送给第三方。

#### 判断文本输入字段是否禁用键盘缓存 (MSTG)

说明：当用户输入字段时，软件会自动建议数据。
静态检测：在存在敏感数据的Activity中对于文本控件的需关闭输入建议及键盘缓存，android:inputType="textNoSuggestions"
动态检测：找到敏感数据相关输入框，输入字符，如果还有建议字段则未关闭
建议：将有敏感信息的Activity输入控件设置为android:inputType="textNoSuggestions"

#### 确定敏感存储数据是否已通过 IPC 机制公开(MSTG)

说明：IPC为进程通讯机制，应防止通过IPC机制对敏感数据进行共享和公开。
静态检测：查看 AndroidManifest.xml 来检测应用程序公开的内容提供程序。确定敏感数据是否通过IPC进程通信机制公开，最好与开发者通过访谈的形式讨论IPC机制共享的数据内容。或者通过代码审计的方式进行检查，如

```
public Cursor query(final Uri uri, final String[] array, final String s, final String[] array2, final String s2) {
    final int match = this.sUriMatcher.match(uri);
    final SQLiteQueryBuilder sqLiteQueryBuilder = new SQLiteQueryBuilder();
    if (match >= 100 && match < 200) {
        sqLiteQueryBuilder.setTables("Passwords");
    }
    else if (match >= 200) {
        sqLiteQueryBuilder.setTables("Key");
    }
    return sqLiteQueryBuilder.query(this.pwdb.getReadableDatabase(), array, s, array2, (String)null, (String)null, s2);
}
```

动态检测：枚举攻击面，将应用程序的包名传递给 Drozer 模块进行检测，详细参考MSTG。

#### 检查用户界面敏感数据是否泄露(MSTG)

说明：许多应用程序要求用户输入多种数据，例如注册账户或付款。当以明文显示数据时，如果应用程序没有正确地隐藏敏感数据，则可能会暴露敏感数据。

#### 为敏感数据测试备份（MSTG-STORAGE-8)

说明：移动操作系统生成的备份中不包含敏感数据程序数据任意备份，App应用数据可被备份导出。
检测：安卓应用AndroidManifest配置文件中android:allowBackup=true，数据备份开关被打开
建议：把配置文件备份开关关掉，即设置android:allowBackup="false"

#### 在自动生成的截图中查找敏感信息(MSTG-STORAGE-9)

说明：自动生成的截图数据中可能含有敏感信息，此类信息存储到本地可能被外部程序获取
检测：通过访谈或全流程运行App后在本地查找是否有敏感数据生成

#### 设备访问安全策略测试 (MSTG)

说明：处理或查询敏感信息的应用程序应该运行在受信任和安全的环境中。

检测：设备是否开启PIN或密码锁，是否开启USB调试等策略

#### 检查内存中的敏感数据(MSTG-STORAGE-10)

说明：APP在内存中存放敏感数据的时间不会超过需要的时间，使用后内存会被明确清除
检测：可以进行代码审计类的检测，如SecretKey的销毁是否安全

#### 测试密码标准算法配置(MSTG-CRYPTO-2, MSTG-CRYPTO-3 and MSTG-CRYPTO-4) 与加密算法的安全性

说明：App本地及服务端加密算法，如签名Token是否安全
检测：主要为静态类代码审计以及交互接口中的加密算法的识别和检查，App中可以对常用的类和接口进行关键字筛查，如Cipher、MessageDigest、Signature、SHA1PRNG

#### 测试随机数的生成 (MSTG)

说明：生成的随机数具有确定性，存在被破解的可能性，安全调用SecureRandom类中的setSeed方法示例如下

```
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
public static void main (String args[]) {
    SecureRandom number = new SecureRandom();
    for (int i = 0; i < 20; i++) {
    System.out.println(number.nextInt(21));
}
```

检测：搜索代码java.util.Random，检查调用是否安全，如Random(seed)带有固定的seed，则安全性降低，多次计算的随机数都相同
建议：用/dev/urandom或/dev/random来初始化伪随机数生成器或者使用java.security.SecureRandom替换java.util.Random

#### 测试密钥管理（MSTG-STORAGE-1，MSTG-CRYPTO-1 和 MSTGCRYPTO-5）

说明：处理密钥内容最安全的方法，就是永远不要把它存储在设备上。密钥在被使用时只存在于内存中的数组中，不再要时就可以归零，尽可能地减少攻击窗口。
检测：通过开发访谈以及代码分析的方式梳理密钥管理机制，可以定位关键常用的类和接口进行筛查，如Cipher、Mac、MessageDigest、Signature、AndroidKeyStore

#### 测试 App 权限 (MSTG-PLATFORM-1)

说明：通过声明使用系统数据和功能所需的权限来请求此访问。根据数据 或功能的敏感和关键程度不同，Android 系统会自动授予权限或询问用户是否同意授予权限。着重检查获取的权限是否与业务需求和属性相匹配，是否存在隐私声明中。
检测：通过检查AndroidManifast.xml中的权限声明确定权限清单，通过MobSF进行权限清单输出

#### 注入缺陷测试（MSTG-PLATFORM-2）

说明：Android 应用程序可以通过自定义 Intent URL scheme 暴露功能。他们可以将功能暴露给其它应用或用户。
检测：可以通过静态代码审计或动态分析的方式进行检测，如使用一段content query查询操作执行注入命令。此外还可以通过Drozer进行注入

```
content query --uri content://sg.vp.owasp_mobile.provider.College/students --where "name='Bob') OR 1=1--''"
```

#### 测试 Fragment 注入（MSTG-PLATFORM-2）

说明：通过导出的PreferenceActivity的子类，没有正确处理Intent的extra值，此为校验或限定不严导致的风险，攻击者可绕过限制访问未授权的界面。
建议：当 API 大于等于19时，强制实现了isValidFragment方法；小于19时，在PreferenceActivity的子类中都要加入isValidFragment ，两种情况下在isValidFragment方法中进行fragment名的合法性校验。

#### 测试自定义 URL Scheme（MSTG-PLATFORM-3）

说明：URL Scheme是一种通过浏览器或App之间互相触发调用的方式，可以触发启动App并且传递参数，在AndroidManifast.xml设置Scheme协议之后，可以通过浏览器或其它App打开对应的Activity，应对传递过来的参数进行过滤，防止恶意调用。攻击者通过访问浏览器构造Intent语法唤起App相应组件，轻则引起拒绝服务，重则可能演变对App进行越权调用甚至升级为提权漏洞。
检测：确定是否已经定义了自定义 URL Scheme，可以在 AndroidManifest.xml 文件中的<intent-filter>元素中找到如<data android:scheme="myapp" android:host="path" />中myapp表示可以通过 myapp://打开。此外可以通过Drozer列举允许通过浏览器打开的URL，命令如下 `run scanner.activity.browsable -a com.google.android.apps.messaging` ；通过以下命令模拟调用 `run app.activity.start --action android.intent.action.VIEW --data-uri "sms://0123456789"`

建议：App对外部调用过程和传输数据进行安全检查或检验，配置category filter, 添加android.intent.category.BROWSABLE方式规避风险。
参考：https://blog.csdn.net/l173864930/article/details/36951805

#### 通过 IPC 测试敏感功能暴露（MSTG-PLATFORM-4）

说明：通过IPC机制可能暴露敏感信息给到其它应用，可能暴露敏感数据的组件：Binder、Services、Bound Services、AIDL、Intents、Content Providers，相关组件开发到IPC的时候尽量使用 permission 标签 (android:permission) 也会限制其它应用程序对组件的访问 。
静态检测：通过分析源码的方式分析是否有暴露敏感信息的逻辑。
动态检测：通过使用Drozer动态分析Content Provider、Activities等组件暴露的地址，详细参考MSTG。
建议：使用 Permission 等权限限制措施。

#### 测试 WebView 中对 JavaScript 执行（MSTG-PLATFORM-5）

说明：检查WebView允许使用JavaScript的风险。Android的webView组件有一个非常特殊的接口函数addJavascriptInterface，能实现本地Java与JS之间交互。在SDK API小于17时或Android版本小于4.1.2时，攻击者利用 addJavascriptInterface这个接口添加的函数，可以远程执行任意代码。
工具：MobSF、安全检测平台
建议：建议开发者不要使用addJavascriptInterface接口或者进行URL白名单过滤或者禁止Android 4.2以下版本运行或进行风险提示

#### 测试 WebView 协议处理程序（MSTG-PLATFORM-6）

说明：WebView 可以加载远程内容，但也可以从应用数据目录或外部存储加载本地内容。如果加载了本地内容，用户就不应该能修改文件名或加载文件的路径，也不应该能编辑加载的文件。
静态检测：分析源代码确保以下推荐配置是否设置，如果开启则确认是否真的是应用正常业务所必需的。

不允许 WebView 对文件的访问。默认情况下文件访问是启用的。 请注意，这仅启用和禁用文件系统访问。App的asset和resource目录的访问不受影响，可通过 file:///android_asset 和 file:///android_res进行访问

```
webView.getSettings().setAllowFileAccess(false);
```

不允许运行在 File Scheme URL 上下文中的 JavaScript 访问来自其它 File Scheme URL 的内容。其在 Android 4.0.3-4.0.4（API level 15）及 以下版本的默认值为 true，在 Android 4.1（API level 16）及以上版本的默认值为 false

```
webView.getSettings().setAllowFileAccessFromFileURLs(false);
```

不允许运行在 file scheme URL 上下文中的 JavaScript 访问任意来源的内容。其在 Android 4.0.3-4.0.4（API level 15）及以下版本的默认 值为 true，在 Android 4.1（API level 16）及以上版本的默认值为 false

```
webView.getSettings().setAllowUniversalAccessFromFileURLs(false);
```

不允许WebView 从安装在系统中的 Content Provider 加载内容，默认情况下启用

```
webView.getSettings().setAllowContentAccess(false);
```

建议：按照以上建议项关闭相关配置。

#### 确保应用程序正确签署(MSTG-CODE-1) 与逆向打包检查

说明：在App中的每个文件都会做一次算法记录，并保存在MANIFEST.MF文件中，我们就可以通过基于MANIFEST.MF文件的安全机制对App包进行完整性校验检测。完整性校验可以在启动App时候触发，如果App被二次打包修改了，那么MANIFEST.MF文件中的校验信息是不一样的。

检测：
1.证书检查（仅检查证书是否正确）：Android Studio有apksigner，位于[SDKPath]/build-tools/[version]，`apksigner verify --verbose Desktop/example.apk` 输出签名版本，通过jarsigner输出证书内容，`jarsigner -verify -verbose -certs example.apk`
2.逆向打包：
a.通过利用AndroidKiller工具对App进行反编译，修改，二次打包并签名；
b.通过apktool进行反编译、修改、打包，再通过SignApk工具进行对App重新签名；
c.验证是否能够正常安装并运行。
参考：https://mp.weixin.qq.com/s?__biz=MzUxODkyODE0Mg==&mid=2247486713&idx=1&sn=967a0a8435add4949a829eeaf2c4c647

#### 测试应用程序是否可调试(MSTG-CODE-2)

说明：检测App应用程序（保护服务端应用）调试信息是否关闭，调试信息中是否写入敏感信息。通过运行App程序，查看logcat等调试日志信息方式，分析是否有泄漏重要的URL地址、提示信息、调试信息等敏感关键字以及程序逻辑的关键流程信息。
检测：检查安卓AndroidManifest.xml配置文件中，若android:debuggable=true则调试开关被打开
建议：把AndroidManifest.xml配置文件中调试开关属性关掉，即设置android:Debugable="false"

#### 调试符号测试(MSTG-CODE-3)

说明：一些元数据，如调试信息、行号和描 述性的函数或方法名称，可以使二进制或字节码更容易被逆向工程师理解，但这些在发行版构建中并不需要，因此可以安全地省略，而不影响应用程序的功能。
检测：通过使用NM或objdump来检查符号表中是否不必要的调试符号，详细参考MSTG。

5.8.4. Testing for Debugging Code and Verbose Error Logging (MSTG-CODE-4) 

#### 检查第三方库中的漏洞(MSTG-CODE-5)

说明：包括第三方SDK，如广告库中的漏洞，识别移动APP使用的所有第三方组件，例如库和框架，并检查已知漏洞

5.8.6. 测试异常处理(MSTG-CODE-6 和 MSTG-CODE-7) 

5.8.7. 内存损坏错误（MSTG-CODE-8） 

#### 环境检测(MSTG-RESILIENCE-1, MSTG-RESILIENCE-5)

说明：包括root环境检查，模拟器检测
建议：APP通过警告用户或终止APP，如果检测到设备有root或越狱

5.10.6. 测试运行时完整性检查(MSTG-RESILIENCE-6) 

5.10.7. 测试混淆(MSTG-RESILIENCE-9) 

#### Activity组件暴露检查

说明：Activity组件的属性exported被设置为true或是未设置exported值但IntentFilter不为空时，Activity被认为是导出的，可通过设置相应的Intent唤起Activity。黑客可能构造恶意数据针对导出Activity组件实施越权攻击。
检测：通过MobSF、在线平台或手动检查AndroidManifest.xml配置
建议：如果组件不需要与其他App共享数据或交互，请将 配置文件中设置该组件为exported = “False”如果组件需要与其他App共享数据或交互， 请对组件进行权限控制和参数校验

#### Service组件暴露检查

说明：Service组件的属性exported被设置为true或是未设置exported值但IntentFilter不为空时，Service被认为是导出的，可通过设置相应的Intent唤起Service。黑客可能构造恶意数据针对导出Service组件实施越权攻击。
检测：通过MobSF、在线平台或手动检查AndroidManifest.xml配置
建议：如果组件不需要与其他App共享数据或交互，请将 配置文件中设置该组件为exported = “False”如果组件需要与其他App共享数据或交互， 请对组件进行权限控制和参数校验

#### ContentProvider组件暴露检查

说明：Content Provider组件的属性exported被设置为true或是Android API<=16时，Content Provider被认为是导出的。黑客可能访问到应用本身不想共享的数据或文件。
检测：通过MobSF、在线平台或手动检查AndroidManifest.xml配置
建议：如果组件不需要与其他App共享数据或交互，请将 配置文件中设置该组件为exported = “False”如果组件需要与其他App共享数据或交互， 请对组件进行权限控制和参数校验

#### BroadcastReceiver组件暴露检查

说明：BroadcastReceiver组件的属性exported被设置为true或是未设置exported值但IntentFilter不为空时，BroadcastReceiver被认为是导出的。导出的广播可以导致数据泄漏或者是越权。
检测：通过MobSF、在线平台或手动检查AndroidManifest.xml配置
建议：如果组件不需要与其他App共享数据或交互，请将 配置文件中设置该组件为exported = “False”如果组件需要与其他App共享数据或交互， 请对组件进行权限控制和参数校验

#### Intent隐式意图调用

说明：封装Intent时采用隐式设置，没有明确指明哪些接收方有权限接收，只设定Action，未限定具体的接收对象，导致Intent可被其他应用获取并读取其中数据。此为校验或限定不严导致的风险。Intent隐式调用发送的意图可被第三方劫持，可以获取intent内容，导致数据泄露，intent劫持，仿冒，钓鱼应用等风险。
检测：在代码内全局搜索在使用Intent启动/唤醒四大组件的地方，判断是否有显示的指定接收方，如有建议中的设置则为显示调用
建议：使用Intent.setPackage、Intent.setComponent、Intent.setClassName、Intent.setClass、new Intent(context,Receivered.class)中任一种方法明确指定目标接收方，显式调用intent。
参考：https://blog.csdn.net/qq_35993502/article/details/120678162

Webview组件远程代码执行（调用getClassLoader）
说明：使用低于17的 API Version，并且在Context子类中使用addJavascriptInterface绑定this对象
危害：通过调用getClassLoader可以绕过google底层对getClass方法的限制
建议：使用大于17的 API Version版本

#### WebView忽略SSL证书错误

说明：WebView调用onReceivedSslError方法时，直接执行handler.proceed()来忽略该证书错误
危害：忽略SSL证书错误可能引起中间人攻击
建议：不要重写onReceivedSslError方法， 或者对于SSL证书错误问题按照业务场景判断，避免造成数据明文传输情况

Webview启用访问文件数据
说明：Webview中使用setAllowFileAccess(true)，App可通过webview访问私有目录下的文件数据
危害：在Android中，mWebView.setAllowFileAccess(true)为默认设置当setAllowFileAccess(true)时，在File域下，可执行任意的JavaScript代码，如果绕过同源策略能够对私有目录文件进行访问，导致用户隐私泄漏
建议：使用WebView.getSettings().setAllowFileAccess(false)来禁止访问私有文件数据

SSL通信服务端检测信任任意证书
说明：自定义SSL x509 TrustManager，重写checkServerTrusted方法，方法内不做任何服务端的证书校验
危害：黑客可以使用中间人攻击获取加密内容
建议：严格判断服务端和客户端证书校验，对于异常事件禁止return 空或者null

HTTPS关闭主机名验证
说明：构造HttpClient时，设置HostnameVerifier时参数使用ALLOW_ALL_HOSTNAME_VERIFIER或HostnameVerifier为空
危害：关闭主机名校验可以导致黑客使用中间人攻击获取加密内容
建议：App在使用SSL时没有对证书的主机名进行校验，信任任意主机名下的合法的证书，导致加密通信可被还原成明文通信，加密传输遭到破坏

SSL通信客户端检测信任任意证书
说明：自定义SSL x509 TrustManager，重写checkClientTrusted方法，方法内不做任何服务端的证书校验
危害：黑客可以使用中间人攻击获取加密内容
建议：严格判断服务端和客户端证书校验，对于异常事件禁止return 空或者null

#### 开放Socket端口

说明：App绑定端口进行监听，建立连接后可接收外部发送的数据
危害：攻击者可构造恶意数据对端口进行测试，对于绑定了0.0.0.0的App可发起远程攻击
建议：如无必要，只绑定本地ip127.0.0.1，并且对接收的数据进行过滤、验证

明文数字证书漏洞
说明：APK使用的数字证书可被用来校验服务器的合法身份，以及在与服务器进行通信的过程中对传输数据进行加密、解密运算，保证传输数据的保密性、完整性。明文存储的数字证书如果被篡改，客户端可能连接到假冒的服务端上，导致用户名、密码等信息被窃取；如果明文证书被盗取，可能造成传输数据被截获解密，用户信息泄露，或者伪造客户端向服务器发送请求，篡改服务器中的用户数据或造成服务器响应异常。

#### AES/DES弱加密

说明：在AES加密时，使用“AES/ECB/NoPadding”或“AES/ECB/PKCS5padding”的模式。当其使用ECB或OFB工作模式时，加密数据可能被选择明文攻击CPA破解
。ECB是将文件分块后对文件块做同一加密，破解加密只需要针对一个文件块进行解密，降低了破解难度和文件安全性。
检测：在代码内全局搜索AES/DES使用的地方，判断工作模式是否为ECB或OFB，若是则存在风险。
建议：禁止使用AES加密的ECB模式，显式指定加密算法为CBC或CFB模式，可带上PKCS5Padding填充AES密钥长度最少是128位，推荐使用256位。
参考：https://blog.csdn.net/qq_35993502/article/details/120718928

AES/DES硬编码密钥
说明：使用AES或DES加解密时，密钥采用硬编码在程序中
危害：通过反编译获取密钥可以轻易解密App通信数据
建议：密钥加密存储或变形后进行加解密运算，不要硬编码到代码中

#### UNZIP解压缩漏洞

说明：解压ZIP文件，使用getName()获取压缩文件时未对名称进行校验，攻击者可构造恶意ZIP文件，被解压的文件将会进行目录跳转被解压到其他目录，覆盖相应，覆盖掉的文件是动态.so、.dex或odex文件，可能导致本地拒绝服务漏洞、任意代码执行漏洞。
检测：检测代码是否有zipEntry相关函数并是否对文件名进行校验
建议：解压文件时，判断文件名是否有../特殊字符，示例代码如下

```
while(( zipEntry = zipInputStream.getNextEntry()) != null ){
    String entryName = zipEntry.getName();
    if(entryName.contains("../")){
        // throw new Exception("bad name")
    }
}
```

Android风险检查清单

https://blog.csdn.net/weixin_40798907/article/details/114579028

组件是否导出

1.APKTool反编译AndroidManifest.xml之后查看

没有配置android:exported且Intent-Filter不为空时，则activity默认为ture，如：

cn.jpush.android.intent.RECEIVE_MESSAGE"

组件可通过以下标签进行权限控制，android:icon="res_string"，android:label="res_string"，android:permissionGroup="res_string"

Android安全检测 - Janus签名漏洞

https://blog.csdn.net/qq_35993502/article/details/122159276

### iOS安全测试检查点

6.2.2. 基本测试操作 

6.3.1. 本地数据存储测试（MSTG-STORAGE-1 和 MSTG-STORAGE-2）

6.3.2. 检查敏感数据日志（MSTG-STORAGE-3） 

6.3.3. 确定敏感数据是否发送给第三方（MSTG-STORAGE-4） 

6.3.4. 在键盘缓存中查找敏感数据（MSTG-STORAGE-5） 

6.3.5. 确定是否通过 IPC 机制暴露敏感数据（MSTG-STORAGE-6） 

6.3.6. 检查用户界面披露的敏感数据（MSTG-STORAGE-7）

6.3.7. 测试敏感数据备份（MSTG-STORAGE-8） 

6.3.8. 测试自动生成的敏感信息截图（MSTG-STORAGE-9） 

6.3.9. 敏感数据存储器测试（MSTG-STORAGE-10） 

6.4.1. 验证加密标准算法（MSTG-CRYPTO-2 和 MSTG-CRYPTO-3）的配置 

6.4.2. 测试密钥管理（MSTG-CRYPTO-1 和 MSTG-CRYPTO-5） 

6.4.3. 测试随机数生成（MSTG-CRYPTO-6） 

说明：所有的随机值都使用足够安全的随机数生成器生成

6.5.1. 测试本地身份验证（MSTG-AUTH-8 和 MSTG-STORAGE-11） 

6.6.1. 应用传输安全（MSTG-NETWORK-2） 

6.6.2. 测试自定义证书存储和证书锁定（MSTG-NETWORK-3 和 MSTGNETWORK-4） 

6.7.1. 测试应用权限(MSTG-PLATFORM-1) 

6.7.2. 通过 IPC 进行敏感功能暴露测试（MSTG-PLATFORM-4）

6.7.3. 测试自定义 URL 方案（MSTG-PLATFORM-3） 

6.7.4. 测试 iOS WebView（MSTG-PLATFORM-5） 

6.7.5. 测试 WebView 协议处理程序（MSTG-PLATFORM-6） 

6.7.6. 确定是否通过 WebViews 公开本地方法（MSTG-PLATFORM-7） 

6.7.7. 测试对象持久性（MSTG-PLATFORM-8） 

6.7.8. 测试强制更新（MSTG-ARCH-9） 

6.8.1. 确保 APP 进行了恰当的签名(MSTG-CODE-1) 

说明：确保APP已签名并提供有效证书

6.8.2. 确定应用程序是否可调试(MSTG-CODE-2) 

6.8.3. 查找调试符号(MSTG-CODE-3) 

6.8.4. 查找调试代码和详细错误日志 (MSTG-CODE-4)

6.8.5. 第三方库的弱点检查(MSTG-CODE-5) 

6.8.6. 测试异常处理 

6.8.7. 内存损坏缺陷(MSTG-CODE-8) 

6.8.8. 确保激活了安全功能(MSTG-CODE-9) 

6.10.1. 越狱检测 (MSTG-RESILIENCE-1) 

建议：APP通过警告用户或终止APP，如果检测到设备有root或越狱

6.10.2. 反调试检查 (MSTG-RESILIENCE-2) 

6.10.3. 文件完整性检查(MSTG-RESILIENCE-3 and MSTG-RESILIENCE-11) 

6.10.4. 设备绑定 (MSTG-RESILIENCE-10) 

组件暴露：建议使用android:protectionLevel="signature" 验证调用来源

### 文件目录遍历类漏洞

Provider文件目录遍历
说明：当Provider被导出且覆写了openFile方法时，没有对Content Query Uri进行有效判断或过滤
危害：攻击者可以利用openFile()接口进行文件目录遍历以达到访问任意可读文件的目的
建议：一般情况下无需覆写openFile方法，如果必要，对提交的参数进行“../”目录跳转符或其他安全校验

### 文件格式解析类漏洞

FFmpeg文件读取
说明：使用了低版本的FFmpeg库进行视频解码
危害：在FFmpeg的某些版本中可能存在本地文件读取漏洞，可以通过构造恶意文件获取本地文件内容
建议：升级FFmpeg库到最新版

安卓“Janus”漏洞
漏洞详情：向原始的App APK的前部添加一个攻击的classes.dex文件(A文件)，安卓系统在校验时计算了A文件的hash值，并以”classes.dex”字符串做为key保存， 然后安卓计算原始的classes.dex文件（B），并再次以”classes.dex”字符串做为key保存，这次保存会覆盖掉A文件的hash值，导致Android系统认为APK没有被修改，完成安装，APK程序运行时，系统优先以先找到的A文件执行，忽略了B，导致漏洞的产生
危害：该漏洞可以让攻击者绕过安卓系统的signature scheme V1签名机制，进而直接对App进行篡改而且由于安卓系统的其他安全机制也是建立在签名和校验基础之上，该漏洞相当于绕过了安卓系统的整个安全机制
建议：禁止安装有多个同名ZipEntry的APK文件

### 内存堆栈类漏洞

未使用编译器堆栈保护技术
说明：为了检测栈中的溢出，引入了Stack Canaries漏洞缓解技术在所有函数调用发生时，向栈帧内压入一个额外的被称作canary的随机数，当栈中发生溢出时，canary将被首先覆盖，之后才是EBP和返回地址在函数返回之前，系统将执行一个额外的安全验证操作，将栈帧中原先存放的canary和.data中副本的值进行比较，如果两者不吻合，说明发生了栈溢出
危害：不使用Stack Canaries栈保护技术，发生栈溢出时系统并不会对程序进行保护
建议：使用NDK编译so时，在Android.mk文件中添加：LOCAL_CFLAGS := -Wall -O2 -U_FORTIFY_SOURCE -fstack-protector-all

未使用地址空间随机化技术
说明：PIE全称Position Independent Executables，是一种地址空间随机化技术当so被加载时，在内存里的地址是随机分配的
危害：不使用PIE，将会使得shellcode的执行难度降低，攻击成功率增加
建议：NDK编译so时，加入LOCAL_CFLAGS := -fpie -pie开启对PIE的支持

libupnp栈溢出漏洞
说明：使用了低于1.6.18版本的libupnp库文件
危害：构造恶意数据包可造成缓冲区溢出，造成代码执行
建议：升级libupnp库到1.6.18版本或以上

### 动态类漏洞

DEX文件动态加载
说明：使用DexClassLoader加载外部的 APK、Jar 或 dex文件，当外部文件的来源无法控制时或是被篡改，此时无法保证加载的文件是否安全
危害：加载恶意的dex文件将会导致任意命令的执行
建议：加载外部文件前，必须使用校验签名或MD5等方式确认外部文件的安全性

动态注册广播
说明：使用Register Receiver动态注册的广播在组件的生命周期里是默认导出的
危害：导出的广播可以导致拒绝服务、数据泄漏或是越权调用
建议：使用带权限检验的Register Receiver
参考：https://blog.csdn.net/qq_35993502/article/details/119348770

### 命令行调用类相关的风险或漏洞

动态链接库中包含执行命令函数：
说明：在Native程序中，有时需要执行系统命令，在接收外部传入的参数执行命令时没有做过滤或检验
危害：攻击者传入任意命令，导致恶意命令的执行
建议：对传入的参数进行严格的过滤

### Mobile Security Check List

https://github.com/OWASP/owasp-mstg/releases

1.1 所有应用程序组件都已识别并且已知
说明：列出组件清单并识别组件业务功能

1.2 安全控制在客户端及服务端均有强制执行
说明：检测各项安全控制措施是否正确执行

1.4 已明确识别在移动应用程序中的敏感信息
说明：明确移动应用中的敏感信息及其存储与展示的位置、方式

1.8 已有明确的策略来管理加密密钥及其生命周期。请遵循NIST SP 800-57等关键管理标准。 
说明：SP800是美国NIST（National Institute of Standards and Technology）发布的一系列关于信息安全的指南（SP是Special Publications的缩写）http://csrc.nist.gov/publications/PubsSPs.html

1.9 已有一种强制更新移动APP的机制
说明：是否有强制更新App或者限制旧版本，以便可以使用

*2.5 在可能包含敏感数据的文本字段上停用剪贴板
说明：对于高度敏感的页面和区域禁用剪切板和截图

*2.9 APP在后台运行时，会从视图中删除敏感数据

3.1 APP不把带有硬编码密钥的对称密码作为唯一的加密方法

4.1 验证服务端与客户端的远程会话身份与鉴权机制
说明：如果APP提供远程服务访问给用户，则需要在服务端执行某种形式的身份验证，例如用户名/密码身份验证。不同权限的用户控制其资源访问和权限的独立。此项为客户端与服务端交互检查的一部分。

4.2 有状态会话管理安全性
说明：如果使用有状态会话管理，则服务端使用随机生成的会话标识符如具备一定有效时限的Token来验证客户端请求，而不发送用户的凭据。并检查失效机制是否正常。

4.4 当用户注销时，服务端终止现有会话
说明：用户注销或销号时，服务端可以终止一切会话

4.6 防重放攻击验证
说明：服务端实现了可以防止多次提交凭据的机制

*4.9 敏感高危操作的MFA验证要求

说明：检查针对敏感高危操作是否设置多个身份验证因素，并且始终强制执行2FA要求

6.2 用户输入验证检查

说明：所有来自外部资源和用户的输入都经过验证，并在必要时进行处理。包括通过UI、IPC机制(如意向、自定义URL和网络源)接收的数据。

6.6 WebViews配置为仅允许所需的最小协议处理程序集（仅支持https）

说明：海云安、MobSF可以检查

8.2 检查App对各种可能存在的恶意行为进行检测并响应
说明：检查App对各种可能存在的恶意行为进行检测并响应，如：
a.APP检测并响应，当被篡改其自己沙箱中的可执行文件和关键数据时。 
b.APP检测并响应，当设备上存在的逆向工程工具和框架时。 
c.APP检测并响应，当有篡改其自己的存储空间中的代码和数据时。
d.APP阻止调试或检测并响应，当设备中存在附加的调试器时。  必须涵盖所有可用的调试协议
e.APP在每个防御类别中实现多种机制，弹性随着所用机制的数量，原创性的多样性而变化。     

8.11 检查静态文件的加密措施
说明：所有属于应用程序的可执行文件和库都在文件级别上进行加密，或者对可执行程序中的重要代码和数据段进行加密或打包。简单的静态分析不会显示重要的代码或数据

### 合规检查

2.12 APP有告知用户所处理的个人身份信息的类型，以及用户在使用APP时应遵循的安全最佳操作

3.3 APP使用适合特定用例的加密原函数，使用符合行业最佳实践的参数进行配置
说明：加密函数需要匹配其场景，如用户登录密码使用SHA-256进行加密

3.5 APP不会为了多种目的重复使用相同的加密密钥
说明：为不同场景使用不同的密钥

4.4 当账号注销时，服务端是否对账号信息进行清除或封存处理
说明：具备账号信息清除机制，并能够有效地执行

5.5 APP不依赖于单个不安全的通信通道作为验证方式
说明：App不使用单一验证方式（电子邮件或SMS）来执行关键操作，例如注册和帐户恢复

6.1 APP仅请求必要的最小权限集
说明：检查权限清单，App获取的权限集合是否是必须权限列表

## Backend与Web安全检查

服务端后台交互检查，利用模拟器安装相应APK包，通过设置代理将流量转发到BurpSuite与XRAY进行流量和抓包分析。按常规Web安全风险进行检测。服务端安全需要关注的是服务端API安全、业务逻辑安全、中间件安全、服务器应用安全。主要可以通过渗透测试的方式对App的服务器进行安全检测，通过模拟恶意攻击方式进行对服务器攻击。从而提高App服务器的安全性。

Web端详细检查点参考“Web安全测试”

### BurpSuite

暴力破解

### HTTP流量抓包

#### 通用抓包

模拟器或局域网手机设置代理，此方法针对HTTP协议进行抓包，部分App可能会检测系统代理而跳过代理

先导出BurpSuite CA证书

然后安卓手机在WiFi处设置，选中WiFi然后修改网络，在高级设置处添加代理

#### Proxifier针对模拟器程序抓包

开启Proxifier，首先在配置文件->代理服务器处配置代理服务器（代理服务器为BurpSuite），其次在配置文件->代理规则处设置，可以设置目标端口为80、443等HTTP协议端口（由于部分模拟器Web协议可能会调用本地的程序如Chrome，所以流量并不在模拟器上）

Proxifier官网：https://www.proxifier.com/download/

#### AVD模拟器抓包

Proxy抓包

首先要开启LTE网络，在模拟器设置（不是手机系统）中找到Proxy设置项设置本地127.0.0.1的代理地址即可

利用Android Studio抓包

Android Studio有内置的网络抓包工具，Profiler，在View->Tool Windows->Profiler中即可打开（最新版为App Inspection），但是目前抓包有流量图没有请求数据详情，

Profiler 抓包参考

https://blog.csdn.net/adayabetter/article/details/109210375

https://dandelioncloud.cn/article/details/1493271719208099842

#### XPosed

XPosed是一个安卓平台的Hook框架，安装XPosed之后还可以安装无数的组件工具

说明：在对部分应用如Narwal的测试中，开启Xposed可能会造成App不能正常运行

JustTrustMe

Github地址https://github.com/Fuzion24/JustTrustMe/releases

部署参考

https://blog.csdn.net/qq_33697094/article/details/111596004

Xposedinstaller 3.1.5

https://forum.xda-developers.com/t/official-xposed-for-lollipop-marshmallow-nougat-oreo-v90-beta3-2018-01-29.3034811/

Xposed SDK列表

https://dl-xda.xposed.info/framework/

Xposed组件列表

https://repo.xposed.info/module-overview

Xposed手动安装参考

https://blog.csdn.net/weixin_38927522/article/details/119832717

Xposed派大星版

https://www.duokaizhushou.cn/xposed

Xposed手动安装以及JustTrustMe

https://blog.csdn.net/weixin_41489908/article/details/119299143

雷电模拟器+Proxifier+BURP绕过APP抓包检测

https://www.freesion.com/article/84581452533/

Xposed+JustTrustMe+Fiddler+夜神模拟器+抖音抓包

https://blog.csdn.net/qq_33697094/article/details/111596004

Xposed夜神模拟器部署教程

https://support.yeshen.com/zh-CN/qt/xp

Xposed安全脉搏文章

https://www.secpulse.com/archives/112022.html

逆向抓包，包括SSL Pinning和No Proxy绕过

https://xz.aliyun.com/t/9843

逆向抓包，多种方案，包括重编译、Frida

https://www.yuanrenxue.com/app-crawl/android-7-capture-data.html

VitualXposed+JustTrustMe

https://blog.csdn.net/weixin_45784666/article/details/115535494

VitualXposed Github

https://github.com/android-hacker/VirtualXposed

Xposed+JustTrustMe

https://blog.csdn.net/qq_33697094/article/details/111596004

#### Troubleshooting

设置系统代理后App没有生效

Android系统设置的代理并不是强制对所有App生效，部分开发框架如Flutter不会使用系统代理，App可以在网络请求类库中通过自定义代理设置，选择是否要走系统代理

```java
// 实现方式
public void run() {
    Looper.prepare();
    OkHttpClient okHttpClient = new OkHttpClient.Builder().
            proxy(Proxy.NO_PROXY).//okhttp不设置代理
            build();
    Request request = new Request.Builder()
            .url("http://www.baidu.com")
            .build();
    Response response = null;
    try {
        response = okHttpClient.newCall(request).execute();
        Toast.makeText(this, Objects.requireNonNull(response.body()).string(), Toast.LENGTH_SHORT).show();
    } catch (IOException e) {
        e.printStackTrace();
    }
    Looper.loop();
}
// 另一种代码
OkHttpClient client = new OkHttpClient.Builder()
.proxySelector(new ProxySelector() {
    @Override
    public List<Proxy> select(URI uri) {
      return Collections.singletonList(Proxy.NO_PROXY);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {

    }
}).build();
```

参考说明：http://t.zoukankan.com/Zdelta-p-14122300.html

### HTTPS抓包

由于有些时候App不会使用系统代理，如使用Flutter框架开发的应用不会使用系统代理，不会信任用户自己安装的证书

#### Drony+System Certification

说明：通过Drony将流量强制转发到代理端口，同时将代理监控软件证书安装到Android系统证书的目录（非用户证书目录）

环境：雷神4模拟器 Android 7.1.2+Drony 1.3.102+BurpSuite

1.开启BurpSuite代理

开启BurpSuite，生成证书（尽量转换为CRT格式）

2.安装证书到系统目录

将生成的BurpSuite证书改一下名字

计算证书HASH哈希值

```
openssl x509 -subject_hash_old -in burpsuite_cacert.crt
```

计算出HASH值后重命名证书文件为 your_hash.0 如269953fb.0

通过adb将其推送到Android系统

查看设备是否连接，赋予root权限并将安全验证关闭

```
adb devices
adb root
adb disable-verity
```

重启手机，重新挂载并将改名后的证书推送到系统证书目录

```
adb root
adb remount
adb push your_hash.0 /system/etc/security/cacerts/
```

推送完文件后再次重启一下

3.设置Drony代理

参考Drony工具的代理设置，设置完代理后即可开始抓包

参考链接：

https://www.cnblogs.com/lulianqi/p/11380794.html

推送证书到模拟器

https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/

#### Frida+Hooker

使用Frida指定just_trust_me将证书验证的部分进行Hook屏蔽掉

https://github.com/CreditTone/hooker

#### Frida Hook Flutter

说明：涉及到通过IDA定位ssl_crypto_x509_session_verify_cert_chain函数，操作比较难

Frida hook Flutter ssl_crypto_x509_session_verify_cert_chain函数进行抓包 

参考链接：

https://www.yuangezhizao.cn/articles/python/Frida/Flutter.html

https://gist.github.com/yuangezhizao/28f392e4795488858be9c248fcc8ca78

https://www.jianshu.com/p/53b53993a7f4

https://blog.csdn.net/yhsnihao/article/details/110477720

https://blog.csdn.net/weixin_39947501/article/details/111299390

IDA的操作

https://blog.csdn.net/victormfc/article/details/118547221

IDA下载地址：https://hex-rays.com/ida-free/

中间人代理

https://docs.mitmproxy.org/stable/

## 在线辅助检测平台

App安全综合检测

利用安全检测平台对App进行综合检测，检测内容包括组件暴露、敏感数据泄露、SSL协议等扫描

| 平台                       | 地址                                         | 备注                       |
| -------------------------- | -------------------------------------------- | -------------------------- |
| 腾讯金刚审计系统           | http://service.security.tencent.com/kingkong | 免费无限制                 |
| 腾讯御安全                 | http://yaq.qq.com/                           | 免费查看漏洞详情需认证     |
| 腾讯哈勃                   | http://habo.qq.com/                          | 恶意软件检测               |
| 360显微镜                  | http://appscan.360.cn/                       | 免费无限制                 |
| 360App漏洞扫描             | http://dev.360.cn/html/vulscan/scanning.html | 免费需要企业或个人实名注册 |
| 百度MTC                    | http://mtc.baidu.com                         | 9.9元/次                   |
| 梆梆                       | https://dev.bangcle.com                      | 免费无限制                 |
| 爱内测                     | http://www.ineice.com/                       | 免费无限制                 |
| 西安交通大学 sanddroid     | http://sanddroid.xjtu.edu.cn/#home           | 免费无限制，比较详细       |
| NAGA                       | http://www.nagain.com/Appscan/               | 免费无限制                 |
| Java decompiler online     | http://www.javadecompilers.com               | Java反编译                 |
| 盘古出品的Janus            | http://appscan.io                            | 需要注册                   |
| *通付盾                    | http://www.appfortify.cn/                    | 链接挂掉了                 |
| *App逆向main_classify_list | https://android.fallible.co/                 | 链接挂掉了                 |
| *GES审计系统               | http://01hackcode.com/                       | 链接挂掉了                 |
| *金山火眼                  | http://fireeye.ijinshan.com/analyse.html     | 链接挂掉了                 |

## 测试工具清单

### Drozer测试

检查点

是否有暴露的组件攻击面

```
run app.package.attacksurface  apk
```

暴露的Activity组件进行攻击

```
run app.activity.info -a apk
```

启动组件信息检查

```
run app.activity.start –-component com.mwr.example.sieve com.mwr.example.sieve.FileSelectActivity
run app.activity.start –-component com.mwr.example.sieve com.mwr.example.sieve.MainLoginActivity
run app.activity.start –-component com.mwr.example.sieve com.mwr.example.sieve.PWList
```

获取Content Provider信息

```
run app.provider.info -a apk
```

获取所有可以访问的URI

```
run scanner.provider.finduris -a apk
```

获取各个URI的数据

```
run app.provider.query  content://com.mwr.example.sieve.DBContentProvider/Passwords
```

针对URI数据进行SQL注入尝试

```
run app.provider.query URI --projection "* FROM SQLITE_MASTER WHERE type='table';--"
```

针对URI获取表中数据

```
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
```

检测SQL注入和目录遍历检查

```
run scanner.provider.injection -a packgeName
run scanner.provider.traversal -a packgeName
```

指定文件路径里全局可写/可读的文件检查

```
run scanner.misc.writablefiles --privileged install_directory

run scanner.misc.readablefiles --privileged install_directory
```

https://www.jianshu.com/p/b43b67f1a419

Drozer常用命令

https://www.jianshu.com/p/8f9d7dc5a8bb

Drozer安装

https://www.jianshu.com/p/4ef5b26dd3fb

Drozer使用

https://www.jianshu.com/p/dfa92bab3a55

Drozer官网

https://labs.f-secure.com/tools/drozer/

Drozer下载地址

https://github.com/mwrlabs/drozer/releases/download/2.4.4/drozer-2.4.4.win32.msi

使用教程

https://labs.f-secure.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf

Drozer检查点参考

https://mp.weixin.qq.com/s?__biz=MzU3MDg2NDI4OA==&mid=2247485067&idx=1&sn=c78cdf701a6d09c943ca2bafe5d4d6d3

### MobSF测试

利用模拟器进行MobSF静态和动态扫描，其中静态可以包括对组件暴露、SSL协议等扫描

https://www.jianshu.com/p/f715d3c6a1c7

动态测试 

- [ ] 进度

MobSF动态测试说明

https://blog.csdn.net/shayuchaor/article/details/65630261

### Frida

Frida安装

首先在https://pypi.org/project/frida/上在相应版本的Download files页面确认Python版本是否有对应安装包，最新的Frida版本可能对应不上当前的Python版本（有的旧版本也可以安装，因为Frida更新很快，最好安装比较新的Python版本）

```
pip install frida==15.1.14
pip install frida-tools
```

```
adb push frida-server /data/local/tmp
adb shell chmod 777 /data/local/tmp/frida-server

adb shell settings put global http_proxy 192.168.31.200:8080
./frida-server &
```

```
frida -U -l fridascript.js -f com.narwal.robot_gloabl --no-pause
```

Frida防止SSL Pinning教程

https://blog.csdn.net/w1590191166/article/details/106308028/

https://blog.csdn.net/qq_18893835/article/details/121461497

检查判断应用架构是Flutter，打开App的页面，查看当前Top层的Activity

```
adb shell dumpsys activity top
```

查看输出是否有“FlutterView”等Flutter字段

Frida工具包Hooker：https://github.com/CreditTone/hooker

利用Frida手动绕过Android APP证书校验 http://www.52bug.cn/cracktool/6380.html

## 反编译检查

通过Apktool、d2j-dex2jar、jd-gui进行反编译破解检查，反编译后对代码进行分析扫描

### 反编译步骤

Apktool反编译资源文件

作用：使用apktool反编译apk，主要查看res文件下xml文件、AndroidManifest.xml和图片，语言资源等文件，如果直接解压.apk文件，xml文件打开全部是乱码

可以参照下方的说明配置环境变量的方式执行

```bash
java -jar apktool.jar d -f apkname.apk -o out_path
```

dex2jar反编译Java源码

作用：将APK包使用压缩软件解压，解压后的目录内有dex文件，将apk反编译成源码，classes.dex转化成jar文件

将dex文件放入dex2jar的目录内使用如下命令即可获取jar包，执行命令后

```bash
D:\Security\dex2jar-2.1>d2j-dex2jar.bat C:\Users\Mia\Desktop\classes.dex
```

也可以直接反编译APK包

```
D:\Security\dex2jar-2.1>d2j-dex2jar.bat -f \path\apk_to_decompile.apk
```

JD-GUI读取Jar文件

使用jd-gui-windows工具打开反编译后的jar文件即可读取源码

接下来就是对反编译后的代码进行分析

#### Apktool

 注意：Apktool 依赖 Java1.8

官网使用说明

*Download Windows [wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat) (Right click, Save Link As `apktool.bat`)*

*Download apktool-2 ([find newest here](https://bitbucket.org/iBotPeaches/apktool/downloads/))*

*Rename downloaded jar to `apktool.jar`*

*Move both files (`apktool.jar` & `apktool.bat`) to your Windows directory (Usually `C://Windows`)*

*If you do not have access to `C://Windows`, you may place the two files anywhere then add that directory to your Environment Variables System PATH variable.*

*Try running apktool via command prompt*

配置完成后执行命令参考

```
apktool d -f C:\Users\Mia\Desktop\one.apk -o C:\Users\Mia\Desktop\output\
```

官网链接：https://ibotpeaches.github.io/Apktool/

下载链接：https://bitbucket.org/iBotPeaches/apktool/downloads/

#### dex2jar

Github地址：https://github.com/pxb1988/dex2jar

#### JD-GUI

JD-GUI下载

https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-windows-1.6.6.zip

参考链接

https://www.jianshu.com/p/e89be5c05a60

https://mp.weixin.qq.com/s?__biz=MzU3MDg2NDI4OA==&mid=2247485067&idx=1&sn=c78cdf701a6d09c943ca2bafe5d4d6d3

https://www.jianshu.com/p/945633724df2

工具打包下载

链接: https://pan.baidu.com/s/1dDmoLcr73oeUOAacFz7m_w 提取码: rr4k

#### APK查壳

使用PKID等工具检查APK是否已经加壳

AndroidKiller反编译工具

安卓开发和安全系列工具

https://www.jianshu.com/p/13459fafb2e0

### 相关工具下载

#### ADB

说明：安装Android Studio的时候也会默认安装ADB，路径为C:\Users\username\AppData\Local\Android\Sdk\platform-tools\

连接调试手机方式

1.USB调试

通过USB连接手机，手机打开开发者模式，启用USB调试，然后输入 `adb devices` 即可看到设备已经连接

2.局域网连接

首先可以通过USB连接手机，使用 `adb tcpip 5555` 命令开启端口监听（可能需要在手机弹窗中开启权限，监听的端口可以设置为其它），然后保持手机同一局域网内断开USB之后可以通过 `adb connect phone_ip_address` 就可以连接到安卓机，连接完成后输入 `adb devices` 验证是否连接。操作完后，建议 `adb disconnect phone_ip_address` 手动断开设备

常用命令

| 命令                                                  | 说明                                                  |
| ----------------------------------------------------- | ----------------------------------------------------- |
| adb tcpip 5555                                        | 开启设备ADB调试端口监听                               |
| adb connect phone_ip_address:port                     | 连接到局域网设备                                      |
| adb devices                                           | 设备清单                                              |
| adb -s device_name root                               | 连接到设备，开启ROOT                                  |
| adb -s 127.0.0.1:5555 shell                           | 连接到设备Shell，其中-s后面可以接上上面设备清单的设备 |
| adb install path\packsge_name                         | 安装程序                                              |
| adb uninstall app_name                                | 卸载程序                                              |
| adb shell pm list packages                            | 查看手机里面所有包名                                  |
| adb shell pm list packages -3                         | 查看手机里面所有第三方包名                            |
| adb shell /system/bin/screencap -p /sdcard/screen.png | 截屏并保存文件在手机上                                |
| adb pull /sdcard/a.png D:/a.png                       | 将手机文件移动到电脑D盘                               |
| adb push D:/a.txt /adcard/a.txt                       | 将电脑文件导入手机                                    |
| adb logcat                                            | 查看日志                                              |
| adb shell cat /sys/class/net/wlan0/address            | 获取手机MAC地址                                       |
| adb shell getprop ro.build.version.release            | 查看Android系统版本号                                 |
| adb shell settings put global http_proxy ip_addr:port | 开启代理                                              |
| adb shell settings put global http_proxy :0           | 关闭代理                                              |

ADB下载链接：http://adbdownload.com/

#### Android Studio

官网：https://developer.android.google.cn/studio/

Android安全工具：https://github.com/eseGithub/AndroidTools

#### 重新打包以及签名

假如你进行了修改，可以使用上一步反编译后生成的目录。重新打包工程中，同样会输出主要步骤的log，重新生成的apk位于目录中的dist目录下，重新生成的apk，是没有经过签名的，不能直接进行安装。

```
apktool b target_directory
```

签名

说明：其中Android Studio有带keytool，在jre\bin路径下

```
keytool -genkey -alias water.keystore -keyalg RSA -validity 40000 -keystore water.keystore
```

重新签名

说明：其中Android Studio有带jarsigner，在jre\bin路径下

```
jarsigner -verbose -keystore water.keystore water.apk water.keystore
```

参考链接：https://blog.csdn.net/qq_41264674/article/details/115860066

## 漏洞扫描

### Nessus

### Netsparker

### PoC检查

#### Vertx-web 跨站请求伪造漏洞

http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202101-1590

#### CSNC-2018-021 - Vert.x - HTTP Header Injection

CNVD-2018-11463

https://seclists.org/bugtraq/2018/Jun/39

Vert.x HTTP头注入漏洞

https://www.cnvd.org.cn/flaw/show/CNVD-2018-11463

## 工具清单

### Ubuntu Anbox

说明：Ubuntu下一个图形化模拟器

```
sudo apt update
sudo apt upgrade
sudo apt install snapd
sudo snap install --beta --devmode anbox
```

安装完后

```
sudo apt install adb
adb devices
```

通过adb命令安装应用，安装完后即可看到应用

```
adb install /tmp/narwal.apk
```

### Drony

安卓强制流量转发App，将流量强制转发到代理端口，可以控制转发哪些App的流量

#### 指定App抓包指南

进入Drony页面后，向右滑动进入到Settings页面，进入到Networks，找到已连接的WiFi，

| 参数                   | 值                     |
| ---------------------- | ---------------------- |
| Hostname               | 设置为代理的IP地址     |
| Port                   | 设置为代理的端口       |
| Proxy type             | 设置为Manual           |
| 下方的第二个Proxy type | 设置为Plain http proxy |
| Filter default value   | 设置为Direct all       |

点击Rules，点击+号新建，设置如下参数，其它保持空。设置完成后点击保存按钮

| 参数        | 值                      |
| ----------- | ----------------------- |
| Action      | 设置为Local proxy chain |
| Application | 选择指定的App           |

设置完成后在主页面往左边滑动到Log页面，点击下方的按钮将其打开为On状态

下载地址：https://files.cnblogs.com/files/lulianqi/Drony_102.apk

### r0capture

安卓应用层抓包通杀脚本

- 限安卓平台，测试安卓7、8、9、10、11 可用 ；
- 无视所有证书校验或绑定，不用考虑任何证书的事情；
- 通杀TCP/IP四层模型中的应用层中的全部协议；
- 通杀协议包括：Http,WebSocket,Ftp,Xmpp,Imap,Smtp,Protobuf等等、以及它们的SSL版本；
- 通杀所有应用层框架，包括HttpUrlConnection、Okhttp1/3/4、Retrofit/Volley等等；
- 无视加固，不管是整体壳还是二代壳或VMP，不用考虑加固的事情；

https://github.com/r0ysue/r0capture

### Postern

安卓系统流量代理工具

使用指南：http://ex.chinadaily.com.cn/exchange/partners/82/rss/channel/cn/columns/snl9a7/stories/WS5f8808d9a3101e7ce97297ac.html

下载地址：https://bbs.csdn.net/topics/603933780

## 术语说明

### 加壳

加壳是在二进制的程序中植入一段代码，在运行的时候优先取得程序的控制权，做一些额外的工作。是应用加固的一种手法对原始二进制原文进行加密/隐藏/混淆。加壳的目的即增加安装包静态分析的难度。

## 代办事项

OWASP

Drozer

Postman代理到Burp和XRAY

burpsuite爆破

## 参考链接

Android渗透测试学习手册中文版

https://wizardforcel.gitbooks.io/lpad/content/ch5.html

Android渗透测试学习手册

https://www.packtpub.com/product/learning-pentesting-for-android-devices/9781783288984

安卓九类漏洞及解决建议（常见的漏洞都在）

https://blog.csdn.net/liuye066/article/details/80619945

Android漏洞参考

https://zhuanlan.zhihu.com/p/371954682

某App渗透测试笔记

https://xz.aliyun.com/t/4703

某iOS渗透测试笔记

https://xz.aliyun.com/t/6953

安卓安全

https://www.jianshu.com/nb/24453921

App安全检测手册

https://cloud.tencent.com/developer/article/1480853?from=article.detail.1633172

安卓测试项参考

https://www.yuque.com/m1tang/itccm5/oqkpdc

[VirusTotal](https://www.virustotal.com/en/file/c7de25cd4a752c28ba5e619d86705f5b90a1a742abedbd849b98c13f7d7f04ef/analysis)恶意软件扫描
