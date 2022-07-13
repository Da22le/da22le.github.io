# Java XMLDecoder反序列化分析


# 简介

XMLDecoder是一套用于对XML进行序列化或反序列化的一套API，它在JDK1.4就已经被开发了出来，它对XML的解析模式并不是更为人所知的DOM解析，而是SAX解析
DOM解析在解析XML时会读取所有数据然后生成DOM树来解析，而SAX则是线性读取XML，所以SAX解析XML性能消耗相对较小

两者区别如下：

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/24737c8e-0aae-b4c9-25a8-c89a38789d98.png)

在Weblogic中由于`was-wast`、`wls9_async`等多个组件使用了XMLDecoder来进行解析xml文档，导致了攻击者可以构造恶意的XML文档来触发反序列化去执行命令，修复方式为采用黑名单禁用object等标签，本文使用jdk7u21去分析XMLDecoder是如何进行操作的

# 反序列化分析

测试代码如下：

```java
import java.beans.XMLDecoder;
import java.io.StringBufferInputStream;

public class Test {
    public static void main(String[] args) {
        String s = "<java version=\"1.7.0_21\">\n" +
                " <object class=\"java.lang.ProcessBuilder\">\n" +
                "  <array class=\"java.lang.String\" length=\"1\">\n" +
                "    <void index=\"0\"><string>calc</string></void>\n" +
                "  </array>\n" +
                "  <void method=\"start\"></void>\n" +
                " </object>\n" +
                "</java>";
        StringBufferInputStream stringBufferInputStream = new StringBufferInputStream(s);
        XMLDecoder xmlDecoder = new XMLDecoder(stringBufferInputStream);
        Object o = xmlDecoder.readObject();
    }
}

```

直接跟进到`xmlDecoder.readObject()`中，这里的`readObject()`并非原生的反序列化`readObject()`只是同名而已

```java
public Object readObject() {
    return (parsingComplete())
            ? this.array[this.index++]
            : null;
}
```

继续跟进到`java.beans.XMLDecoder#parsingComplete`中，通过`XMLDecoder.this.handler.parse()`去解析`XMLDecoder.this.input`，而input就是封装过的传进去的xml

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/af2206f3-094f-2b4d-a683-7ec399682d87.png)

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7768dd16-1389-7e0c-495d-7fecdfc8f9ce.png)

在`com.sun.beans.decoder.DocumentHandler#parse`中通过SAX的工厂模式创建实例并且调用SAX解析，而其中`DocumentHandler.this`是xml对应标签进行解析处理的Handler

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/25c03251-6ecf-cecd-385b-e823c00e2731.png)

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b60ed3fe-b2fc-2e51-de58-ce2af01e8175.png)

继续跟进到`com.sun.org.apache.xerces.internal.jaxp.SAXParserImpl#parse`中，先进行设置`Handler`然后继续解析

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/9f7913b6-314c-3e1b-ce3b-282260f4e8ad.png)

进入到重载的`SAXParserImpl#parse`中继续跟进

![7.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d02bea85-6459-70d8-3272-4b61e12f9221.png)

在`AbstractSAXParser#parse`中，将`inputSource`的值赋值给`xmlInputSource`并继续解析

![8.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/6c5d94dd-6791-8025-7ea0-48c9583ee10f.png)

在`XMLParser#parse`中，然后使用`XML11Configuration#parse`继续对其解析

![9.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/bce13c03-763e-ece9-5b39-6fb642b5ca40.png)

继续往下走然后在`XML11Configuration#parse(boolean)`中进入到`fCurrentScanner.scanDocument()`中

![10.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/f2bfba24-9227-dd63-3464-49c01231cd87.png)

在`XMLDocumentFragmentScannerImpl#scanDocument`中通过`do while`循环对xml文档进行遍历解析，其中主要解析方法是在`next()`中实现

![11.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b5a1e919-638b-23f0-f629-db4c59180b0b.png)

最后在`com.sun.beans.decoder.DocumentHandler#startElement`中开始对第一个开始标签进行解析，第一个标签为`<java>`，通过`this.getElementHandler(var3).newInstance()`得到`JavaElementHandler`的实例并赋值给`this.handler`，然后对`Owner`和`Parent`的值进行设置，接下来在for循环中对标签内部的属性进行遍历取值，其中`var4.getQName(var6)`是对标签内部的属性名称取值，`var4.getValue(var6)`是对属性的值进行取值，最后调用`addAttribute`设置属性

![12.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/8eef782c-ab69-3d7b-6b08-28b765aca940.png)

![13.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5b9802b5-100d-2149-67b6-2ba4af325633.png)

然后继续对`object`标签进行遍历进行取值赋值，接下来以同样的操作对其它的开始标签进行遍历解析，直到开始解析第一个结束标签`</string>`

![14.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/9b6e2027-ead0-4461-3365-09e98b126a38.png)

在解析第一个结束标签`</string>`时，调用`this.handler.endElement()`，其中`StringElementHandler`中没有会根据继承关系调用父类`ElementHandler`的`endElement()`中

![15.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e2df1f42-151e-d390-d472-c8ba096232cd.png)

最后在`StringElementHandler#getValueObject`中将值取出，然后返回一个存有该值的`ValueObjectImpl`实例

![16.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/2c9dc6ae-0b92-8dc9-63b9-12519b4f787b.png)

然后在`ElementHandler#endElement`中，将`ValueObjectImpl`的值取出交给`this.parent`的`Handler`也就是`VoidElementHandler`，这里是交给`<string>`的父标签也就是`<void>`标签，其中是将值存储在了数组中

```xml
<void index="0"><string>calc</string></void>
```

![17.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/0818f163-4427-875b-29cc-6b466bf47397.png)

![18.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/1e79ee9d-30de-4c1f-e451-d7fc881e85a6.png)

接下来处理`</void>`标签，最后在`ObjectElementHandler#getValueObject`中，通过`this.getContextBean()`得到var3的类`String`，在通过`var4 = var2.length == 2 ? "set" : "get"`将`set`赋值给var4，最后new了一个`Expression`实例，并执行`var5.getValue()`将存有`calc`的数组set进去

![19.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/7aa88231-6352-140e-3b01-bf59b7dfa312.png)

![20.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/26d2368a-ef27-8dd3-8900-1e3b23e2bc85.png)

然后继续处理`</array>`标签，通过`this.parent.addArgument`，将存有`calc`的数组添加到上一标签也就是`<object>`标签的handler`ObjectElementHandler`中

![21.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/a4fed592-f53f-c197-43b3-fec283f45f26.png)

![22.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/81ee8495-a8b5-b737-f284-d0a8c94417b9.png)

接下来处理`<void method="start"></void>`，在处理`</void>`时，在`ObjectElementHandler#getValueObject`中先通过`this.getContextBean()`得到了`new ProcessBuilder("calc")`，然后在通过`var4 = this.method != null && 0 < this.method.length() ? this.method : "new";`的判断将`start`赋值给var4，然后new了一个`Expression`实例，最后执行`var5.getValue()`，此时拼接为`new ProcessBuilder("calc").start()`，通过反射弹出计算器

![23.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/5eae7de4-0c81-6ca4-53df-62f584f1c1b9.png)

# 参考链接

1. https://cloud.tencent.com/developer/article/1957183




