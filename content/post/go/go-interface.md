---
title: "Go接口"
date: 2019-02-04T15:22:51+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---


## 接口的定义

接口类型是对其它类型行为的抽象和概括；因为接口类型不会和特定的实现细节绑定在一起，通过这种抽象的方式我们可以让我们的函数更加灵活和更具有适应能力。

很多面向对象的语言都有相似的接口概念，但Go语言中接口类型的独特之处在于它是满足隐式实现的。也就是说，我们没有必要对于给定的具体类型定义所有满足的接口类型；简单地拥有一些必需的方法就足够了。这种设计可以让你创建一个新的接口类型满足已经存在的具体类型却不会去改变这些类型的定义；当我们使用的类型来自于不受我们控制的包时这种设计尤其有用。

接口（interface）定义了一个对象的行为规范，只定义规范不实现，由具体的对象来实现规范的细节。接口类型是一种抽象的类型。它不会暴露出它所代表的对象的内部值的结构和这个对象支持的基础操作的集合；它们只会展示出它们自己的方法。也就是说当你有看到一个接口类型的值时，你不知道它是什么，唯一知道的就是可以通过它的方法来做什么。

```go
package main
import "fmt"
type canSay interface{
	Say()
}
type dog struct {
	name string
}
type cat struct {
	name string
}
func (d dog) Say() {
	fmt.Println(d.name,"say")
}
func main() {
	var tom2 canSay
	tom := dog{name: "汤姆"}
	tom2 = tom
	tom2.Say() // 汤姆 say
	mi := cat{name: "猫咪"}
	tom2 = mi  // 报错 因为cat没有实现接口规定的say方法
}
```

## 接口值

接口值，由两个部分组成，一个具体的类型和那个类型的值。它们被称为接口的动态类型和动态值。在我们的概念模型中，一些提供每个类型信息的值被称为类型描述符，比如类型的名称和方法。在一个接口值中，类型部分代表与之相关类型的描述符。

```go
package main
import (
	"bytes"
	"fmt"
	"io"
	"os"
)
func main() {
	var w io.Writer
	fmt.Printf("类型:%T,值:%v\n",w,w) // 类型:,值:
	w = os.Stdout
	fmt.Printf("类型:%T,值:%v\n",w,w) // 类型:*os.File,值:&{0xc00007e280}
	w = new(bytes.Buffer)
	fmt.Printf("类型:%T,值:%v\n",w,w) // 类型:*bytes.Buffer,值:
	w = nil
	fmt.Printf("类型:%T,值:%v\n",w,w) // 类型: 类型:
}
```

**一个包含nil指针的接口不是nil接口**

## 类型断言

类型断言是一个使用在接口值上的操作。语法上它看起来像x.(T)被称为断言类型，这里x表示一个接口的类型和T表示一个类型。一个类型断言检查它操作对象的动态类型是否和断言的类型匹配。

x.(T)T表示类型

```go
package main
import (
	"bytes"
	"fmt"
	"io"
	"os"
)
func main() {
	var w io.Writer
	w = os.Stdout
	f := w.(*os.File) 
	fmt.Printf("类型%T,值:%v\n",f,f) // 类型*os.File,值:&{0xc00014a280}
	c := w.(*bytes.Buffer)
	fmt.Printf("类型%T,值:%v\n",c,c) // panic
}
```

判断是什么类型:

```go
package main
import (
	"fmt"
)
func judgeType(x interface{}) {
	switch v := x.(type) {
	case string:
		fmt.Printf("is string:%v\n", v)
	case int:
		fmt.Printf("is int:%v\n", v)
	case bool:
		fmt.Printf("is bool:%v\n", v)
	default:
		fmt.Println("donot know ")
	}
}
func main() {
	judgeType(1)      // is int:1
	judgeType(true)   // is bool:true
	judgeType("true") // is string:true
	judgeType(1.22)   // donot know
}
```

## 空接口

### 空接口的定义

空接口是**没有定义任何方法的接口。因此任何类型都实现了空接口。空接口类型的变量可以存储任意类型的变量。**

```go
package main
import "fmt"
func main() {
	var test interface{}
	t1 := 1
	test = t1
	fmt.Printf("类型:%T 值:%v\n",test,test) // 类型:int 值:1
	t2 := "zhaohaiyu"
	test = t2
	fmt.Printf("类型:%T 值:%v\n",test,test) // 类型:string 值:zhaohaiyu
	t3 := false
	test = t3
	fmt.Printf("类型:%T 值:%v\n",test,test) // 类型:bool 值:false
	t4 := 3.14
	test = t4
    fmt.Printf("类型:%T 值:%v\n",test,test) // 类型:float64 值:3.14
}
```

### 空接口的应用

1.  **空接口作为函数的参数**

```go
func show(test interface{}) {
	fmt.Printf("类型:%T 值:%v\n",test,test)
}
```

2. **空接口作为map的值**

```go
var studentInfo = make(map[string]interface{})
studentInfo["name"] = "赵海宇"
studentInfo["age"] = 18
fmt.Println(studentInfo) // map[age:18 name:赵海宇]
```