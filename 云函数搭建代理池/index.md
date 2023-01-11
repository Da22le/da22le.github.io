# 云函数搭建代理池


# 云函数的理解

- 云函数（Serverless Cloud Function，SCF）是云计算厂商为企业和开发者们提供的无服务器执行环境，可在无需购买和管理服务器的情况下运行代码， 是实时文件处理和数据处理等场景下理想的计算平台。只需使用 SCF 平台支持的语言编写核心代码并设置代码运行的条件，即可在某云基础设施上弹性、安全地运行代码。

- 无服务器（Serverless）不是表示没有服务器，而表示在使用 Serverless 时，我们无需关心底层资源，也无需登录服务器和优化服务器，只需关注最核心的代码片段，即可跳过复杂的、繁琐的基本工作。使用云函数（SCF）时，我们只需使用平台支持的语言（Python、Node.js、PHP、Golang、Java 及 Custom Runtime）编写代码，云计算厂商将完全管理底层计算资源，包括服务器 CPU、内存、网络和其他配置/资源维护、代码部署、弹性伸缩、负载均衡、安全升级、资源运行情况监控等。

**原理图如下**

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/47acc67f-3915-9299-eb47-219c2f5fa877.png)

# 代理池搭建

所需要的工具如下：

1. [SCFProxy](https://github.com/shimmeris/SCFProxy)
2. [腾讯云云函数](https://console.cloud.tencent.com/scf/list?rid=1&ns=default)
3. [mitmproxy](https://github.com/mitmproxy/mitmproxy)

进入函数服务->选择自定义地区->进入新建

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/367e2e02-80e2-7e14-2335-cf304789ae3e.png)

选择从头开始->选择运行环境为Python3.6->选择在线编辑，其中内容为`SCFProxy/HTTP/src/server.py`其中`SCF_TOKEN`可自定义，如要更改需同`client.py`一起修改

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e489338f-c0b1-bf1d-a376-1868612f665f.png)

函数服务创建成功后->选择触发管理->创建触发器->触发方式选择API网关触发

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/2f74df65-77a7-288e-52b2-dfbcc67115fb.png)

访问路径接下来需填入`SCFProxy/HTTP/src/client.py`的`scf_servers: List[str] = []`中

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d169f255-c0f4-f93c-450b-d9f0d85db66c.png)

接下来通过mitmproxy提供本地代理进行运行

> mitmproxy证书在`C:\Users\[用户名]\.mitmproxy`下选择信任并安装即可

运行以下命令即可：

```
mitmdump -s client.py -p 8081 --no-http2
```

如在VPS上运行需将`block_global`参数设置为false

```
mitmdump -s client.py -p 8081 --no-http2 --set block_global=false
```

**效果如下：**

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/071ae7eb-ad7a-72cb-39c4-f4dda76987ac.png)

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f8ef5a0c-6ee2-305f-2ca0-491b7ffbdcb6.png)

# 参考链接

1. https://cloud.tencent.com/document/product/583/9705

