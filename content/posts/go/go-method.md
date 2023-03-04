---
title: "Go方法"
date: 2019-02-02T15:18:16+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
featuredImagePreview: /img/go.webp
---


## 方法声明

在函数声明时，在其名字之前放上一个变量，即是一个方法。这个附加的参数会将该函数附加到这种类型上，即相当于为这种类型定义了一个独占的方法。

```go
package main
import "fmt"
type People struct {
	name string
	age  uint8
}
func (p People) SayHello() {
	fmt.Println(p.name, ": hello world")
	p.age = 20
}
func main() {
	p := People{name: "zhaohaiyu", age: 18} 
	p.SayHello()   // zhaohaiyu : hello world
	fmt.Println(p.age)	//18
}
```

## 基于指针对象的方法

当调用一个函数时，会对其每一个参数值进行拷贝，如果一个函数需要更新一个变量，或者函数的其中一个参数实在太大我们希望能够避免进行这种默认的拷贝，这种情况下我们就需要用到指针了。

```go
package main
import "fmt"
type People struct {
	name string
	age  uint8
}
func (p *People) SayHello() {
	fmt.Println(p.name, ": hello world")
    p.age = 20
}
func main() {
	p := People{name: "zhaohaiyu", age: 18} 
	p.SayHello()   // zhaohaiyu : hello world
    fmt.Println(p.age)	// 20
}
```

调用时p为person的结构体对象,SayHello是People结构体指针的方法,在go中可以直接调用,亦可以(&p).SayHello()

**Nil也是一个合法的接收器类型**

```go
package main
import "fmt"
type MySlice []int
func (m *MySlice) sum() int {
	var num int
	for _, i := range *m {
		num += i
	}
	return num
}
func main() {
	m := MySlice{1,2,3,4,5}
	fmt.Println(m.sum()) // 15
	m = nil
	fmt.Println(m.sum()) // 0
}
```

## 封装

一个对象的变量或者方法如果对调用方是不可见的话，一般就被定义为“封装”。封装有时候也被叫做信息隐藏，同时也是面向对象编程最关键的一个方面。

Go语言只有一种控制可见性的手段：大写首字母的标识符会从定义它们的包中被导出，小写字母的则不会。这种限制包内成员的方式同样适用于struct或者一个类型的方法。因而如果我们想要封装一个对象，我们必须将其定义为一个struct。

这也就是前面的小节中IntSet被定义为struct类型的原因，尽管它只有一个字段：

```go
type IntSet struct {
    words []uint64
}
```

当然，我们也可以把IntSet定义为一个slice类型，尽管这样我们就需要把代码中所有方法里用到的s.words用*s替换掉了：

```go
type IntSet []uint64
```