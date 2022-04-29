# RMI原理和反序列化


# RMI原理

`RMI(Remote Method Invocation)`即Java远程方法调用是一种用于实现远程过程调用的应用程序接口。RMI实现了Java程序之间JVM的远程通信。
RMI框架如下：

![1.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/b4ba9278-06e5-b49f-8cca-bb68514f7160.png)

RMI底层采用了`Stub(客户端)`和`Skeleton(服务端)`机制，调用方法大致如下：
1. RMI客户端先创建`Stub(sun.rmi.registry.RegistryImpl_Stub)`
2. Stub会将Remote对象传递给`远程引用层(java.rmi.server.RemoteRef)`并且创建`java.rmi.server.RemoteCall(远程调用)对象`
3. `RemoteCall`会序列化`RMI服务名称`和`Remote对象`
4. 远程引用层会将序列化后的请求信息通过`Socket`连接的方式传输到`RMI服务端`的远程引用层
5. RMI服务端的`远程引用层(sun.rmi.server.UnicastServerRef)`收到请求后传递给`Skeleton(sun.rmi.registry.RegistryImpl_Skel#dispatch)`
6. Skeleton会调用`RemoteCall`进行反序列化
7. Skeleton处理客户端请求：`bind`、`list`、`lookup`、`rebind`、`unbind`，如果是`lookup`则查找RMI服务名绑定的接口对象，序列化该对象并通过RemoteCall传输到客户端
8. RMI客户端反序列化服务端结果，获取远程对象的引用
9. RMI客户端调用远程方法，RMI服务端反射调用RMI服务实现类的对应方法并序列化执行结果返回给客户端
10. RMI客户端反序列化RMI远程方法调用结果

实现RMI所需的API：
1. java.rmi：提供客户端需要的类、接口和异常
2. java.rmi.server：提供服务端需要的类、接口和异常
3. java.rmi.registry：提供注册表的创建以及查找和命名远程对象的类、接口和异常

接下来上代码：
服务端代码

```
package rmi;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    // RMI服务器IP地址
    public static String HOST = "127.0.0.1";
    // RMI服务端口
    public static int PORT = 8989;
    public static String RMI_PATA = "/hello";
    // RMI服务名称
    public static final String RMI_NAME = "rmi://" + HOST + ":" + PORT +RMI_PATA;

    public static void main (String [] args){
        try {
            // 注册RMI端口
            LocateRegistry.createRegistry(PORT);
            // 创建一个服务
            RMIInterface rmiInterface = new RMIImpl();
            // 服务命名绑定
            Naming.rebind(RMI_NAME,rmiInterface);

            System.out.println("启动RMI服务在"+ RMI_NAME);

        }catch (Exception e){
            e.printStackTrace();
        }
    }
}

```

在8989端口起了一个RMI服务，以`rmi://127.0.0.1:8989/hello`对应一个`RMIImpl`类实例，然后通过`Naming.rebind(RMI_NAME,rmiInterface)`绑定对用关系

服务端RMIInterface代码：

```
package rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface RMIInterface extends Remote {
    String hello() throws RemoteException;
}

```

定义了一个继承`Remote`的接口，具体实现代码在`RMIImpl.java`中
代码如下：

```
package rmi;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RMIImpl extends UnicastRemoteObject implements RMIInterface {
    protected RMIImpl() throws RemoteException{
        super();
    }

    @Override
    public String hello() throws RemoteException{
        System.out.println("call hello().");
        return "this is hello().";
    }
}

```

继承了`UnicastRemoteObject`并实现了`RMIInterface`接口，重写了`hello()`方法，`UnicastRemoteObject`类提供了很多支持RMI的方法，这些方法可以通过JRMP协议导出一个远程对象的引用，并通过动态代理构建一个可以和远程对象交互的Stub对象

接下来看客户端代码：

```
package rmi;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import static rmi.RMIServer.RMI_NAME;

public class RMIClient {
    public static void main(String[] args) {
        try {
            // 获取服务注册器
            Registry registry = LocateRegistry.getRegistry("127.0.0.1",8989);
            // 获取所有注册的服务
            String[] list = registry.list();
            for (String i : list){
                System.out.println("已经注册的服务：" + i);
            }

            // 寻找RMI_NAME对应的RMI实例
            RMIInterface rt = (RMIInterface) Naming.lookup(RMI_NAME);
            // 调用Server的hello()方法,并拿到返回值
            String result = rt.hello();

            System.out.println(result);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}

```

其中通过`Naming.lookup(RMI_NAME)`寻找对应的实例，这样就拿到了远程对象，可通过远程对象调用`hello()`方法

具体实现效果如下：

![2.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/bc84b29a-a324-b561-9fd8-cb01c1f06350.png)

![3.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/e0da3a83-cf54-df54-9e96-17bd769ace9b.png)

# RMI反序列化漏洞

在RMI中传输数据时，是使用序列化传输的，相应的就一定会进行反序列化数据，而在Java中，只要进行反序列化操作就可能会有漏洞，RMI通过序列化传输Remote对象，如果我们构造了一个恶意的Remote对象，那么在服务端进行反序列化时，就会触发反序列化漏洞

可以借用`ysoserial`去触发漏洞

![4.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/66ea68d9-42d6-29e9-d07f-d765c2cf60ae.png)

> 因为本身jdk版本限制，借用了@Y4er师傅的图，下面两张也是

客户端会在`sun.rmi.registry.RegistryImpl_Stub#bind`中进行序列化

![5.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/3c8034ae-2ce2-0a8c-9519-9ea6688292d7.png)

服务端会在`sun.rmi.registry.RegistryImpl_Skel#dispatch `中进行反序列化

![6.png](https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/2513662/d9318d4c-23bf-d340-e52c-88909fda8d7d.png)

> 两个类都是动态生成类

# RMI-JRMP反系列化

JRMP接口的两种常见实现方式：
1. JRMP协议(Java Remote Message Protocol)，RMI专用的Java远程消息交换协议
2. IIOP协议(Internet Inter-ORB Protocol) ，基于 CORBA 实现的对象请求代理协议

> JRMP和RMI利用过程一样

# 参考连接

1. https://y4er.com/post/java-rmi/
2. https://zhishihezi.net/c/5d644b6f81cbc9e40460fe7eea3c7925

