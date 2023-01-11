# ZOHO ManageEngine OpManager 两个RCE


# 前言

最近在审计opmanager，正好爆了rce来学习一下

# 第一个RCE（CVE-2022-37024）

环境直接官网下载，一路下一步即可

漏洞描述是：允许经过身份验证的用户进行数据库更改，从而导致NMAP功能中的远程代码执行。也就是说可以分为两点一是：如何修改数据库的内容。二是：找执行nmap操作时从数据库中提取并拼接的参数

报着这样的想法先来看一波补丁，这里用的是125657和125658，在`com.adventnet.netutils.fw.nmap.utils.NmapUtil#getNmapInitialOption`中删除了一个`ADDITIONAL_COMMAND`字段，该字段进入到`IPAMUseBean.getIPAMPropertyString(keys)`中从数据库`IPAMProperty`的表中取出value值，然后返回拼接到nmap中返回一串字符串，而且从该函数的名字就可以看出初始化nmap参数，到这里猜测八九不离十了

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/957066fa-b05b-8c2d-7e2d-8f396a2aafa4.png)

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/87b6ee22-23c7-cbba-951a-16de3d2f0a9a.png)

接着就去找执行nmap命令的函数，在`com.adventnet.netutils.fw.nmap.utils.NmapCmdExecutor#runNmapCommand`中找到了函数，先打个断点方便一会调试，这里标记了一下`envs.put("PATH", path)`，是一个坑，这里设置了一下`PATH`环境变量导致了**在执行命令时必须加上绝对路径比如：C:\Windows\System32\calc.exe**才能够执行命令

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/380e8d3d-03b4-513d-c281-3696683cbb95.png)

然后就又找了一会sql注入（修改数据库内容，第一眼看见就以为是sql注入实际上并不是），没找到就去测功能点看是不是在功能点中能传入数据，也没找到（全都是ip一类的而且做了正则），到这里又换个思路先去测试一下那个功能点能够触发先前找的`runNmapCommand`函数（万一一开始就找错了呢）

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/adbdfc6d-ad7f-53f3-4fad-f32970bbbef2.png)

分别在拼接`ADDITIONAL_COMMAND`和最后执行`start()`时打上断点，在测试网络扫描器时分别先后触发，这样看来思路没错，接下来就是去找怎么修改`ADDITIONAL_COMMAND`的值

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ce1ff773-15df-a870-1b69-84af3630244f.png)

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0bbe5726-8705-3e3e-332a-9878c6da4bc8.png)

就继续翻补丁，在`com.adventnet.netutils.networkmgmt.IPAddressManagerActionForwarder#updateGeneralSettings`中，找到了对`DNS_SERVER`参数进行了过滤，然后执行了sql操作，这里就想着sql注入改`ADDITIONAL_COMMAND`的值在通过功能去触发nmap到最后执行命令（此时脑子就有点懵没仔细看表，其实两张表不同而且并不能堆叠注入直接修改），有目标了就接着就往上回溯在`com.adventnet.netutils.api.admin.AdminRequestHandler#updateIPAMSettings`中找到了触发点

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5c42e728-1874-3ecd-e422-34f5e614ff58.png)

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/181ebe70-0da4-4d07-25a1-23f6e4cb3e89.png)

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6b81e4be-8000-5fe4-9b95-13d13b8970dc.png)

看到接收的请求是request，就想是不是servlet但是没有继承httpservlet，那么就有可能是其它路由转发，这样的话就不是很好找了，到这里没有思路了，就只能笨办法打断点功能点一个一个点，找了一会没有触发，这时候Y4er师傅闪亮登场亲手调试了一番，发现了这个点并不能修改`ADDITIONAL_COMMAND`的值，也就是一开始找的数据库的点就错了，然后就继续找在`com.adventnet.netutils.fw.nmap.utils.NmapUtil#getDNSResolveOption`中找到了这个点，从数据库拿出`DNS_SERVER`的值，然后返回值最后拼接到nmap语句中（一开始我以为是修复了sql注入的点，还是自己经验不太够），那么修复`ADDITIONAL_COMMAND`应该单纯就是为了防止也像`DNS_SERVER`一样，但是更彻底直接给删了

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/70d52c81-c8fb-e030-97bc-7fc264a42614.png)

接下来就是找`DNS_SERVER`注入的点，全局搜索到了`updateIPAMSettings`类的路由，接着直接根据给定的param构造数据包，成功将`C:\Windows\System32\calc.exe`传了进去

![11.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/803270de-06af-19f8-5b7d-ac3fd282e0ed.png)

![12.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e9a06fd4-57db-2655-bb4c-ecf33d0496e3.png)

接着打断点调试，成功拼接

![13.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/a886f0f1-6a2f-5c68-da7a-ee2c23eafb6c.png)

然后尝试传入`& |`等尝试执行命令，但是在执行nmap操作前`DNS_SERVER`会先经过两次过滤，分别是插入数据库前和拼接到nmap命令前，先经过以下正则匹配传入数据库，在将所有空白字符替换，最后才拼接到nmap中，到这里一直绕不过限制执行命令

![14.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ec656e8d-8c6e-d5a4-1cfc-ea4961e36165.png)

![15.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/27baa3b2-0e1d-e37a-fdd5-cc1f62cc8ebd.png)

# 另一个RCE（CVE-2022-38772）

当我看见另一个rce漏洞描述的时候，人其实是懵的，所以`ADDITIONAL_COMMAND`也是可以和`DNS_SERVER`一样拼接到nmap操作里，触发命令注入的，那么当时没找到肯定就是漏了一个重要的关键点，因此我就又一个一个将补丁看了一下，果然发现了两个点：一个是`com.adventnet.netutils.api.ipam.IPAMAPIUtil#configureNmapScanOptions`里，另外一个是在`com.adventnet.ncm.api.impl.SettingsRESTApiModule#executeDBQueryConsole`中

先来看第一个，删了`ADDITIONAL_COMMAND`，并且删除了从request提取`ADDITIONAL_COMMAND`的操作，那么这个应该是可以从api直接访问并且构造恶意包内容的

![16.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d2527964-96ca-cbd9-fabb-5c20245a12a4.png)

![17.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0283773c-f877-3843-3d3b-db9c69fcb2ee.png)

接着全局搜索找到了相应路由和参数，但是配置文件里没有配置`ADDITIONAL_COMMAND`参数，构造数据包测试一下果然报错，找了一下没有办法绕过

![18.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/08b51ac4-6636-80fa-3757-0ec8307d33f7.png)

![19.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/860e3ebf-fc75-9f37-a04c-2a7d29ad623a.png)

然后就继续翻补丁，找到了一个执行sql操作的地方，从request中提出`QUERY_STRING`的值，然后传入到`RunQuery`中执行sql操作，这里做了校验只是从`QUERY_STRING`中取出前6个字符判断不能为：insert、delete、drop，其中并没有限制update那么可以直接修改`DNS_SERVER`的值从而绕过第一次正则匹配，但是不能绕过空白字符替换，另外也可以通过`;`绕过其限制，直接插入`ADDITIONAL_COMMAND`的值

![20.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7970676b-8af2-963c-2100-0924a2b72201.png)

全局搜索找到调用`executeDBQueryConsole`的路由，而且`QUERY_STRING`没有校验，那么直接构造数据包向`IPAMProperty`表中插入数据

![21.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7d9e0c80-aa5c-cee8-0e3b-a21a0d4db936.png)

这里直接插入时提示最大长度为100，那么就先随便插入在通过update修改值即可

![22.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/665d6406-00c3-bab9-c5ff-580f3403d0db.png)

![23.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/660a90a5-5f1d-d624-9220-ebbd28d69dbb.png)

最后来看一下执行nmap时，拼接的参数

![24.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/caa5162b-ca2d-bd47-f588-5b0148146e01.png)

还有另外一个路由`/api/json/ipam/addDHCPServer`也可以触发nmap操作，但是依然不能够结合apikey达到未授权rce的效果

# 小结

opmanager前段时间还爆了一个获取apikey的洞，[文章在这](https://y4er.com/posts/cve-2022-36923-manageengine-opmanager-getuserapikey-authentication-bypass/)，但是这个apikey并不能调用这几个路由，因此少了一环没有能够未授权rce，但是`/api/json/ncmsettings/executeDBQuery`可以通过apikey调用可以执行sql操作，这次审漏洞收获不少，多了许多的思路能够运用到以后的挖洞中，也有不足，经验不够还要多审计提升经验
# 参考连接

1. https://www.manageengine.com/itom/advisory/cve-2022-37024.html
2. https://www.manageengine.com/itom/advisory/cve-2022-38772.html


