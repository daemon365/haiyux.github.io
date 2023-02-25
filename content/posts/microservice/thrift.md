---
title: "thrift的介绍及其使用"
date: 2021-01-19T20:10:55+08:00
draft: false
toc: true
categories: [microservice]
tags: [微服务,Thrift]
authors:
    - haiyux
---

## 什么是thrift

Thrift是Facebook于2007年开发的跨语言的rpc服框架，提供多语言的编译功能，并提供多种服务器工作模式；用户通过Thrift的IDL（接口定义语言）来描述接口函数及数据类型，然后通过Thrift的编译环境生成各种语言类型的接口文件，用户可以根据自己的需要采用不同的语言开发客户端代码和服务器端代码。

例如，我想开发一个快速计算的RPC服务，它主要通过接口函数getInt对外提供服务，这个RPC服务的getInt函数使用用户传入的参数，经过复杂的计算，计算出一个整形值返回给用户；服务器端使用java语言开发，而调用客户端可以是java、c、python等语言开发的程序，在这种应用场景下，我们只需要使用Thrift的IDL描述一下getInt函数（以.thrift为后缀的文件），然后使用Thrift的多语言编译功能，将这个IDL文件编译成C、java、python几种语言对应的“特定语言接口文件”（每种语言只需要一条简单的命令即可编译完成），这样拿到对应语言的“特定语言接口文件”之后，就可以开发客户端和服务器端的代码了，开发过程中只要接口不变，客户端和服务器端的开发可以独立的进行。

Thrift为服务器端程序提供了很多的工作模式，例如：线程池模型、非阻塞模型等等，可以根据自己的实际应用场景选择一种工作模式高效地对外提供服务；

**Thrift的官方网站：http://thrift.apache.org/**

## thrift的协议结构

![](/images/2344773-20210820220337430-196389488.png)

![](/images/2344773-20210820220346538-1880550238.png)

Thrift是一种c/s的架构体系。TServer主要任务是高效的接受客户端请求，并将请求转发给Processor处理。

- 最上层是用户自行实现的业务逻辑代码；
- Processor是由thrift编译器自动生成的代码，它封装了从输入数据流中读数据和向数据流中写数据的操作，它的主要工作是：从连接中读取数据，把处理交给用户实现impl，最后把结果写到连接上。
- TProtocol是用于数据类型解析的，将结构化数据转化为字节流给TTransport进行传输。从TProtocol以下部分是thirft的传输协议和底层I/O通信。
- TTransport是与底层数据传输密切相关的传输层，负责以字节流方式接收和发送消息体，不关注是什么数据类型。
- 底层IO负责实际的数据传输，包括socket、文件和压缩数据流等。

## 下载

下载thrift编译软件:

- MacOs:`brew install thrift`
- Windows:Thrift官方下载地址：http://thrift.apache.org/download

golang下载: `go get github.com/apache/thrift/lib/go/thrift`

python下载: `sudo pip install thrift`

## IDL文件编写

 thrift 采用IDL（Interface Definition Language）来定义通用的服务接口，并通过生成不同的语言代理实现来达到跨语言、平台的功能。在thrift的IDL中可以定义以下一些类型：基本数据类型，结构体，容器，异常、服务

### 基本类型

- bool: 布尔值 (true or false), one byte
- byte: 有符号字节
- i16: 16位有符号整型
- i32: 32位有符号整型
- i64: 64位有符号整型
- double: 64位浮点型
- string: Encoding agnostic text or binary string

基本类型中基本都是有符号数，因为有些语言没有无符号数，所以Thrift不支持无符号整型。

### 特殊类型

binary: Blob (byte array) a sequence of unencoded bytes

这是string类型的一种变形，主要是为[Java](http://lib.csdn.net/base/javase)使用，目前我主要使用C++的语言，所以java的这个类型没有用过

### struct

thrift中struct是定义为一种对象，和面向对象语言的class差不多.,但是struct有以下一些约束：

- struct不能继承，但是可以嵌套，不能嵌套自己。
- 其成员都是有明确类型
- 成员是被正整数编号过的，其中的编号使不能重复的，这个是为了在传输过程中编码使用。
- 成员分割符可以是逗号（,）或是分号（;），而且可以混用，但是为了清晰期间，建议在定义中只使用一种，比如C++学习者可以就使用分号（;）。
- 字段会有optional和required之分和protobuf一样，但是如果不指定则为无类型—可以不填充该值，但是在序列化传输的时候也会序列化进去，optional是不填充则部序列化，required是必须填充也必须序列化。
- 每个字段可以设置默认值
- 同一文件可以定义多个struct，也可以定义在不同的文件，进行include引入。

数字标签作用非常大，但是随着项目开发的不断发展，也许字段会有变化，但是建议不要轻易修改这些数字标签，修改之后如果没有同步客户端和服务器端会让一方解析出问题。

```go
struct Report {  
	1: required string msg, //改字段必须填写  
	2: optional i32 type = 0; //默认值  
	3: i32 time //默认字段类型为optional 
}
```

规范的struct定义中的每个域均会使用required或者 optional关键字进行标识。如果required标识的域没有赋值，Thrift将给予提示；如果optional标识的域没有赋值，该域将不会被序列化传输；如果某个optional标识域有缺省值而用户没有重新赋值，则该域的值一直为缺省值；如果某个optional标识域有缺省值或者用户已经重新赋值，而不设置它的__isset为true，也不会被序列化传输。

### 容器（Containers）

　　Thrift容器与目前流行编程语言的容器类型相对应，有3种可用容器类型：

- list<t>: 元素类型为t的有序表，容许元素重复。对应c++的vector，java的ArrayList或者其他语言的数组（官方文档说是ordered list不知道如何理解？排序的？c++的vector不排序）
- set<t>:元素类型为t的无序表，不容许元素重复。对应c++中的set，java中的HashSet,python中的set，php中没有set，则转换为list类型了
- map<t,t>: 键类型为t，值类型为t的kv对，键不容许重复。对用c++中的map, Java的HashMap, PHP 对应 array, Python/Ruby 的dictionary。

　　容器中元素类型可以是除了service外的任何合法Thrift类型（包括结构体和异常）。为了最大的兼容性，map的key最好是thrift的基本类型，有些语言不支持复杂类型的key，JSON协议只支持那些基本类型的key。

容器都是同构容器，不失异构容器。

例子

```go
struct Test {
  1: map<Numberz, UserId> user_map,
  2: set<Numberz> num_sets, 
  3: list<Stusers> users
}
```

### 枚举（enmu）

很多语言都有枚举，意义都一样。比如，当定义一个消息类型时，它只能是预定义的值列表中的一个，可以用枚举实现。说明：

- 编译器默认从0开始赋值
- 可以赋予某个常量某个整数
- 允许常量是十六进制整数
- 末尾没有分号
- 给常量赋缺省值时，使用常量的全称

　　注意，不同于protocal buffer，thrift不支持枚举类嵌套，枚举常量必须是32位的正整数

```go
enum EnOpType {CMD_OK = 0, // (0)  
               CMD_NOT_EXIT = 2000, // (2000) 
               CMD_EXIT = 2001, // (2001) 　　
               CMD_ADD = 2002 // (2002)
              }
struct StUser {
  1: required i32 userId;
  2: required string userName;
  3: optional EnOpType cmd_code = EnOpType.CMD_OK; // (0)
  4: optional string language = “english”
}
```

### 常量定义和类型定义

　　Thrift允许定义跨语言使用的常量，复杂的类型和结构体可使用JSON形式表示。

```go
const i32 INT_CONST = 1234; const EnOpType myEnOpType = EnOpType.CMD_EXIT; //2001
```

　说明：分号可有可无。支持16进制。　　

Thrift支持C/C++类型定义。

```go
typedef i32 MyInteger // a 
typedef StUser ReU // b 
typedef i64 UserId
```

　说明：a.末尾没有逗号。b. Struct也可以使用typedef。

### 异常（Exceptions）

　　Thrift结构体在概念上类似于（similar to）C语言结构体类型—将相关属性封装在一起的简便方式。Thrift结构体将会被转换成面向对象语言的类。

　　异常在语法和功能上类似于结构体，差别是异常使用关键字exception，而且异常是继承每种语言的基础异常类。

```go
exception Extest { 
  1: i32 errorCode,
  2: string message,
  3: StUser userinfo
}
```

### 服务（Services）

　　服务的定义方法在语义(semantically)上等同于面向对象语言中的接口。Thrift编译器会产生执行这些接口的client和server stub。具体参见下一节。

　　在流行的序列化/反序列化框架（如protocal buffer）中，Thrift是少有的提供多语言间RPC服务的框架。这是Thrift的一大特色。

　　Thrift编译器会根据选择的目标语言为server产生服务接口代码，为client产生stubs。

```go
service SeTest {   void ping(),   bool postTweet(1: StUser user);   
    StUser searchTweets(1:string name);  
    oneway void zip()
}　
```

- 首先所有的方法都是纯虚汗数，也就是继承类必须实现这些方法
- 返回值不是基本类型的都把返回值放到了函数参数中第一个参数，命名_return
- 所有的参数（除返回值）都是const类型，意味这函数一般参数无法作为返回值携带者。只会有一个返回参数，如果返回值有多个，那只能封装复杂类型作为返回值参数。
- oneway的返回值一定是void
- 当然服务是支持继承。
- 服务不支持重载

### 名字空间（Namespace）

Thrift中的命名空间类似于C++中的namespace和java中的package，它们提供了一种组织（隔离）代码的简便方式。名字空间也可以用于解决类型定义中的名字冲突。

由于每种语言均有自己的命名空间定义方式（如[Python](http://lib.csdn.net/base/python)中有module）, thrift允许开发者针对特定语言定义namespace：

```
namespace go com.example.test
namespace py com.example.test  
namespace php com.example.test  
```

### 注释（Comment）

　　Thrift支持C多行风格和Java/C++单行风格。

```go
/* 
* This is a multi-line comment. 
* Just like in C. 
*/ 
// C++/Java style single-line comments work just as well.
```

### 11Includes

　　便于管理、重用和提高模块性/组织性，我们常常分割Thrift定义在不同的文件中。包含文件搜索方式与c++一样。Thrift允许文件包含其它thrift文件，用户需要使用thrift文件名作为前缀访问被包含的对象，如：

```go
include "test.thrift"    
... 
struct StSearchResult {    
  1: in32 uid;
  ... 
}
```

thrift文件名要用双引号包含，末尾没有逗号或者分号
## Thrift支持的传输及服务模型

### 支持的传输格式：

| 参数:               | 描述:                                              |
| :------------------ | -------------------------------------------------- |
| TBinaryProtocol     | 二进制格式                                         |
| TCompactProtocol    | 压缩格式                                           |
| TJSONProtocol       | JSON格式                                           |
| TSimpleJSONProtocol | 提供JSON只写协议, 生成的文件很容易通过脚本语言解析 |
| TDebugProtocol      | 使用易懂的可读的文本格式，以便于debug              |

### 支持的数据传输方式：

| 参数:            | 描述:                                                        |
| ---------------- | ------------------------------------------------------------ |
| TSocket          | 阻塞式socker                                                 |
| TFramedTransport | 以frame为单位进行传输，非阻塞式服务中使用                    |
| TFileTransport   | 以文件形式进行传输                                           |
| TMemoryTransport | 将内存用于I/O. java实现时内部实际使用了简单的ByteArrayOutputStream |
| TZlibTransport   | 使用zlib进行压缩， 与其他传输方式联合使用。当前无java实现    |

### 支持的服务模型：

| 参数:              | 描述:                                                        |
| ------------------ | ------------------------------------------------------------ |
| TSimpleServer      | 简单的单线程服务模型，常用于测试                             |
| TThreadPoolServer  | 多线程服务模型，使用标准的阻塞式IO                           |
| TNonblockingServer | 多线程服务模型，使用非阻塞式IO（需使用TFramedTransport数据传输方式） |

## 代码实现

### 编写\*.thrift文件

```go
namespace go example

struct Data {
    1: string text
}

service format_data {
    Data do_format(1:Data data),
}
```

解析成go代码:`thrift --out . --gen go example.thrift`

解析成python代码:`thrift --out . --gen py example.thrift`

### golang服务端

服务端的实现:

1. Handler      
   - 服务端业务处理逻辑。这里就是业务代码，比如 计算两个字符串 相似度
2. Processor  
   - 从Thrift框架 转移到 业务处理逻辑。因此是RPC调用，客户端要把 参数发送给服务端，而这一切由Thrift封装起来了，由Processor将收到的“数据”转交给业务逻辑去处理
3. Protocol     
   - 数据的序列化与反序列化。客户端提供的是“字符串”，而数据传输是一个个的字节，因此会用到序列化与反序列化。
4. Transport   
   -  传输层的数据传输。
5. TServer     
   -  服务端的类型。服务器以何种方式来处理客户端请求
   -  TSimpleServer —— 单线程服务器端使用标准的阻塞式 I/O
   -  TThreadPoolServer —— 多线程服务器端使用标准的阻塞式 I/O
   -  TNonblockingServer —— 多线程服务器端使用非阻塞式 I/O

```go
/* server.go */

package main

import (
	"context"
	"fmt"
	"log"
	"test/example"

	"github.com/apache/thrift/lib/go/thrift"
)

type FormatDataImpl struct{}

func (fdi *FormatDataImpl) DoFormat(ctx context.Context) (r string, err error) {
	return "不好", nil
}

const (
	HOST = "127.0.0.1"
	PORT = "8080"
)

func main() {

	handler := &FormatDataImpl{}
	processor := example.NewFormatDataProcessor(handler)
	serverTransport, err := thrift.NewTServerSocket(HOST + ":" + PORT)
	if err != nil {
		log.Fatalln("Error:", err)
	}
	transportFactory := thrift.NewTBufferedTransportFactory(10000000)
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()

	server := thrift.NewTSimpleServer4(processor, serverTransport, transportFactory, protocolFactory)
	fmt.Println("Running at:", HOST+":"+PORT)
	err = server.Serve()
	if err != nil {
		log.Fatalln("Error:", err)
	}
}
```

### python服务端

```python
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport
from example import format_data

__HOST = '127.0.0.1'
__PORT = 8080

class FormatDataImpl:
    def do_format(self):
        return "你好"

if __name__ == '__main__':
    handler = FormatDataImpl()
    processor = format_data.Processor(handler)
    transport = TSocket.TServerSocket('127.0.0.1', 8080)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

    print("Starting python server...")
    server.serve()
    print("done!")
```

### golang客户端

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"test/example"

	"github.com/apache/thrift/lib/go/thrift"
)

const (
	HOST = "127.0.0.1"
	PORT = "8080"
)

func main() {
	tSocket, err := thrift.NewTSocket(net.JoinHostPort(HOST, PORT))
	if err != nil {
		log.Fatalln("tSocket error:", err)
	}
	transport := thrift.NewTBufferedTransport(tSocket,10000000)
	// transport, err := transportFactory.Gwt(tSocket)
	// if err != nil {
	// 	log.Fatalln("GetTransport error:", err)
	// }
	protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()

	client := example.NewFormatDataClientFactory(transport, protocolFactory)

	if err := transport.Open(); err != nil {
		log.Fatalln("Error opening:", HOST+":"+PORT)
	}
	defer transport.Close()

	// data := example.Data{Text: "hello,world!as赵海宇"}
	d, err := client.DoFormat(context.TODO() )
	fmt.Println(d)
}

```

5.python客户端

```python
from example import format_data
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

try:
    # Make socket
    transport = TSocket.TSocket('127.0.0.1', 8080)
    # Buffering is critical. Raw sockets are very slow
    transport = TTransport.TBufferedTransport(transport)

    # Wrap in a protocol
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client to use the protocol encoder
    client = format_data.Client(protocol)

    # Connect!
    transport.open()

    # data = format_data.Data(text="sada")
    d = client.do_format()
    print(d)
    transport.close()
except Thrift.TException as tx:
    print(tx.message)
```

## 常见的坑

1. golang中倒入包路径有`github.com/apache/thrift/lib/go/thrift`和`git.apache.org/thrift.git/lib/go/thrift` 要统一用一个,不然会出问题
2. golang中 thrift的新版实现的结构体多一个`ctx context.Context`参数.(老版本没有,网上很多的demo代码用新版的thrift会报错)
3. 客户端以及服务端对应好传输及服务模型协议,不同会报错.

## 参考文章

- https://www.cnblogs.com/hapjin/p/8075721.html
- https://blog.csdn.net/houjixin/article/details/42778335
- https://www.jianshu.com/p/4723ce380b0e
