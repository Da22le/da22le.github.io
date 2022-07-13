# JDK7u21反序列化分析


# 前言

继续学习反序列化，这个链子正好用到了前面fastjson反序列化的`TemplatesImpl`类，这里就不详细讲解该类的具体用法，有兴趣的请看我上一篇fastjson反序列化文章和cc2分析文章

# 环境复现

这里直接引用了`ysoserial.jar`这个包，使用其自带的paylaod

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6e86badc-391c-feef-a27d-75052173452a.png)

```java
import ysoserial.payloads.Jdk7u21;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class JDK7u21 {
    public static void main(String[] args) {
        try {
            Object calc = new Jdk7u21().getObject("calc");

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();//用于存放person对象序列化byte数组的输出流

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(calc);//序列化对象
            objectOutputStream.flush();
            objectOutputStream.close();

            byte[] bytes = byteArrayOutputStream.toByteArray(); //读取序列化后的对象byte数组

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);//存放byte数组的输入流

            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            Object o = objectInputStream.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

# 漏洞分析

首先来看一下`LinkedHashSet`这个类，它继承了`HashSet`并实现了`Serializable`可以进行反序列化，其`readObject()`方法在父类`HashSet`中

```java
public class LinkedHashSet<E>
    extends HashSet<E>
    implements Set<E>, Cloneable, java.io.Serializable
```

在其方法内会对map进行put操作，其中`PRESENT`是new了一个Object空对象

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/26ee83c9-f049-ec24-b6fd-26b33cec71d6.png)

```java
 private static final Object PRESENT = new Object();
```

进入到`java.util.HashMap#put`中，在if判断语句内有这样一个关键的点`key.equals(k)`，为什么它是关键呢？我们知道在动态代理中有这么一个知识点：**动态代理对象每执行一个方法时，都会被转发到实现InvocationHandler接口类的invoke方法**。也就是说在反序列化时我们将一个动态代理的对象放入到map中，在该方法中执行`key.equals(k)`时就会触发代理类的`invoke`方法

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/30774eb5-06a0-0456-0a11-c967a875d7af.png)

在`AnnotationInvocationHandler`类的`invoke`方法中，会对动态代理对象执行的方法名字进行判断，当为`equals`时会进入到`equalsImpl`中

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/1aa3ca3f-bffe-7319-12c4-66db3a7a65a2.png)

在`equalsImpl`中会对传进来的var1类中的方法进行遍历，并通过`var8 = var5.invoke(var1)`去调用其方法，可以看到当我们传进去的类为`TemplatesImpl`时，会遍历出`getOutputProperties`方法并且去调用该方法，而我们知道调用了`getOutputProperties`就会最后触发`TemplatesImpl.newTransformer()`然后进行实例化触发恶意操作

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f2bc55ae-b21b-b91d-e3e1-1940bc070b5d.png)

这样整条链子就齐了，通过javassist构造一个恶意类，然后对LinkedHashSet进行反序列化触发，其中肯定是需要满足一些条件的，这里就不提TemplatesImpl要满足的点，来看一下在触发`key.equals(k)`时需要满足的点，这是整个链子最厉害的点

先来看一下第一次进行`map.put()`传进去的值是什么，可以看见第一次是传进去的`TemplatesImpl`类

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f3b8869f-c193-7771-1c84-fcc57aaa605e.png)

然后获取`key`的hash，在通过`indexFor()`获取hash的索引值，然后在for循环中根据索引值进行判断，其中`table`是一个Entry数组，用来存放我们传进来的键值对，为了后续对新的value和老的value进行判断，其中还有这么一个条件`e != null`，但是这是我们第一次传进来的键值对，`Entry`本身就是空的，因此直接跳过循环进行自增，并放入到`Entry`中

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/881de719-0333-3ddb-ee45-35b23ba27f77.png)

```java
    transient Entry<K,V>[] table;
```

第二次进行`map.put()`传进去的值是我们封装的`AnnotationInvocationHandler`对象

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d2ac6bbf-ca2c-7098-05a0-b132a6474dd1.png)

这一次就会触发`key.equals(k)`，但是这里我们需要满足两个条件，才会去触发`key.equals(k)`

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/55a96a90-f769-2f35-43e9-cfc08dd2df9d.png)

```java
e.hash == hash && ((k = e.key) == key || key.equals(k))
```

- e.hash == hash 为true
- (k = e.key) == key 为false

其中`e.hash == hash`要为true就是说从`Entry`中提取的hash要和传进来的key的hash要一致，而我们知道for循环是为了更新相同key的value值（其中相同key的判断条件为hash值相等），可是我们传进来的两个key根本就不相同分别是`TemplatesImpl`和封装的`AnnotationInvocationHandler`代理对象，如何让其hash相等呢？这里用到了一个新的知识点**hash碰撞**

> hash碰撞就是指两个不同的字符串计算得到的hash值相同

继续看，在第二次进行`map.put()`时，进行hash值的计算，会通过`k.hashCode()`计算hash值，而此时k为动态代理对象，它会触发执行`AnnotationInvocationHandler`的`invoke`方法

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/18e87c98-ce42-e609-8898-93ffc67ad3fc.png)

其中进行判断，如果动态代理对象执行的方法名为`hashCode`时，进入到`hashCodeImpl()`中

![11.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5fa0e570-9e88-2cbd-ef6c-31d2bd46f227.png)

在`hashCodeImpl()`中，通过迭代器对`memberValues`对象进行遍历，其中存放着我们传进去的键值对

![12.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0f2139dc-8c3a-8c4d-789c-9f5466c52201.png)

![13.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f096e357-7651-4ab4-ca9d-68f99ad334a1.png)

来看下面这段代码，其中通过异或来获取hash值赋值给var1，其中`127 * ((String)var3.getKey()).hashCode()`对传进来的key值进行获取hash，此时key为`f5a5a608`，而它的hash值为0，然后`memberValueHashCode(var3.getValue())`是对传进来的value值进行获取hash，其中如果值不为数组的话返回hash

```java
var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())
```

![14.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/fea2fbe5-ce0c-72be-5b32-05770b98d3e3.png)

我们知道0和任何数字进行异或，得到的结果都为被异或数的本身，而此时value为`TemplatesImpl`，也就是说在第二次进行`map.put()`时，进行hash值的计算得到的hash值为`TemplatesImpl`的hash和第一次传进来的一样，这样会在`java.util.HashMap#put`中符合for循环的判断，为相同hash的key进行value的替换，此时会进入到if条件语句中

```java
e.hash == hash && ((k = e.key) == key || key.equals(k))
```

此时`e.hash == hash`为true，而`(k = e.key) == key`必定为false因为是比较两次传进来的key是否相等，而我们传进来的两个key分别是`TemplatesImpl`和封装的`AnnotationInvocationHandler`代理对象，因此这个条件也满足，然后就会触发`key.equals(k)`，执行恶意操作

# 参考链接

1. https://mp.weixin.qq.com/s/qlg3IzyIc79GABSSUyt-OQ
2. https://forum.90sec.com/t/topic/1707/1
3. https://y4er.com/post/ysoserial-jdk7u21/



