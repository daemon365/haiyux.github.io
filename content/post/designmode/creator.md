---
title: "创建者模式"
date: 2022-04-23T16:28:58+08:00
draft: false
toc: true
categories: 
- "design mode"
tags: 
- 设计模式
authors:
    - haiyux
---



## 单例模式

### 为什么要用单例模式

**保证一个对象只有一个实例** ，减少内存开销。比如一些可以复用一个连接的网络，比如`http2 client`等，而且可以减少网络开销。

### 为什么不用个全局变量控制

因为任何代码都有可能覆盖掉那些变量的内容， 从而引发程序崩溃。

### 代码实现

```go
package main

import (
	"fmt"
	"sync"
)

type Single struct {
}

var single *Single
var once = &sync.Once{}

func NewSingle() *Single {
	once.Do(func() {
		single = &Single{
			// 初始化
		}
	})
	return single
}

func main() {
	for i := 0; i < 1000; i++ {
		s := NewSingle()
		fmt.Printf("create %d,address %p\n", i, s)
	}
}

/*
结果：
create 0,address 0x1164fe0
create 1,address 0x1164fe0
create 2,address 0x1164fe0
create 3,address 0x1164fe0
create 4,address 0x1164fe0
create 5,address 0x1164fe0
create 6,address 0x1164fe0
create 7,address 0x1164fe0
create 8,address 0x1164fe0
...
*/
```

## 工厂模式

我们在创建对象时不会对客户端暴露创建逻辑，并且是通过使用一个共同的接口来指向新创建的对象。比如电脑支持`intel cpu`，现在要支持`amd cpu`，我们就可以让所有`cpu`实现接口。

### 简单工厂模式

实现简单，不适合复杂场景

```go
package main

import (
	"errors"
	"fmt"
)

// 工厂接口
type CpuFactory interface {
	Run() string
}

type IntelCpu struct{}

func (*IntelCpu) Run() string {
	return "intel cpu is running"
}

type AmdCpu struct{}

func (*AmdCpu) Run() string {
	return "amd cpu is running"
}

func NewCpu(name string) (CpuFactory, error) {
	switch name {
	case "intel":
		return &IntelCpu{}, nil
	case "amd":
		return &AmdCpu{}, nil
	default:
		return nil, errors.New("no such cpu")
	}
}

func main() {
	c1, err := NewCpu("intel")
	if err != nil {
		panic(err)
	}
	fmt.Println(c1.Run())
	c2, err := NewCpu("amd")
	if err != nil {
		panic(err)
	}
	fmt.Println(c2.Run())
	_, err = NewCpu("other")
	fmt.Println(err)
}
/*
结果：
intel cpu is running
amd cpu is running
no such cpu
*/
```

### 工厂方法模式

大部分时候，我们创建对象要创建很多逻辑，比如初始化变量，从远端请求`config`等等。这是我们需要每次`struct`提供个创建方法。

```go
package main

import (
	"errors"
	"fmt"
)

// 工厂接口
type CpuFactory interface {
	Run() string
}

type IntelCpu struct{}

func (*IntelCpu) Run() string {
	return "intel cpu is running"
}

func NewIntelCpu() *IntelCpu {
	// 做创建逻辑
	return &IntelCpu{}
}

type AmdCpu struct{}

func (*AmdCpu) Run() string {
	return "amd cpu is running"
}

func NewAmdCpu() *AmdCpu {
	// 做创建逻辑
	return &AmdCpu{}
}

func NewCpu(name string) (CpuFactory, error) {
	switch name {
	case "intel":
		return NewIntelCpu(), nil
	case "amd":
		return NewAmdCpu(), nil
	default:
		return nil, errors.New("no such cpu")
	}
}

func main() {
	c1, err := NewCpu("intel")
	if err != nil {
		panic(err)
	}
	fmt.Println(c1.Run())
	c2, err := NewCpu("amd")
	if err != nil {
		panic(err)
	}
	fmt.Println(c2.Run())
	_, err = NewCpu("other")
	fmt.Println(err)
}
/*
结果：
intel cpu is running
amd cpu is running
no such cpu
*/
```

### 抽象工厂模式

抽象工厂模式则是针对的多个产品等级结构， 我们可以将一种产品等级想象为一个产品族，所谓的产品族，是指位于不同产品等级结构中功能相关联的产品组成的家族。用于复杂场景，比如`amd`和`intel`都生成`cpu`和`gpu`

```go
package main

import "fmt"

// 抽象工厂接口
type ElementAbstractFactory interface {
	CreateCpu() Cpu // cpu
	CreateGpu() Gpu // Gpu
}

func GetElementAbstractFactory(brand string) (ElementAbstractFactory, error) {
	if brand == "intel" {
		return &intel{}, nil
	}

	if brand == "amd" {
		return &amd{}, nil
	}

	return nil, fmt.Errorf("Wrong brand type passed")
}

// cpu 具体工厂
type Cpu interface {
	Run() string
}

type Gpu interface {
	Graphics() string
}

type intel struct{}

func (*intel) CreateCpu() Cpu {
	return &intelCpu{}
}

func (*intel) CreateGpu() Gpu {
	return &intelGpu{}
}

type intelCpu struct{}

func (*intelCpu) Run() string {
	return "intel cpu is running"
}

type intelGpu struct{}

func (*intelGpu) Graphics() string {
	return "intel gpu is working on graphics"
}

type amd struct{}

func (*amd) CreateCpu() Cpu {
	return &amdCpu{}
}

func (*amd) CreateGpu() Gpu {
	return &amdGpu{}
}

type amdCpu struct{}

func (*amdCpu) Run() string {
	return "amd cpu is running"
}

type amdGpu struct{}

func (*amdGpu) Graphics() string {
	return "amd gpu is working on graphics"
}

func main() {
	e, _ := GetElementAbstractFactory("intel")
	cpu := e.CreateCpu()
	gpu := e.CreateGpu()
	fmt.Println(cpu.Run())
	fmt.Println(gpu.Graphics())
	e2, _ := GetElementAbstractFactory("amd")
	cpu2 := e2.CreateCpu()
	gpu2 := e2.CreateGpu()
	fmt.Println(cpu2.Run())
	fmt.Println(gpu2.Graphics())
}
/*
intel cpu is running
intel gpu is working on graphics
amd cpu is running
amd gpu is working on graphics
*/
```

## 生成器模式

在对其进行构造时需要对诸多成员变量和嵌套对象进行繁复的初始化工作。 这些初始化代码通常深藏于一个包含众多参数且让人基本看不懂的构造函数中； 甚至还有更糟糕的情况， 那就是这些代码散落在客户端代码的多个位置。比如在`go`中，就可以利用指针传递完成初始化。

```go
package main

import "fmt"

// Computer 是生成器接口
type Computer interface {
	Cpu()
	Gpu()
}

type Director struct {
	builder Computer
}

// NewDirector ...
func NewDirector(builder Computer) *Director {
	return &Director{
		builder: builder,
	}
}

// Construct Product
func (d *Director) Construct() {
	d.builder.Cpu()
	d.builder.Gpu()
}

type Computer1 struct {
	cpu string
	gpu string
}

func (c *Computer1) Cpu() {
	c.cpu = "intel"
}

func (c *Computer1) Gpu() {
	c.gpu = "nvida"
}

type Computer2 struct {
	cpu string
	gpu string
}

func (c *Computer2) Cpu() {
	c.cpu = "amd"
}

func (c *Computer2) Gpu() {
	c.gpu = "amd"
}

func main() {
	c1 := Computer1{}
	d := NewDirector(&c1)
	fmt.Printf("%+v\n", c1)
	d.Construct()
	fmt.Printf("%+v\n", c1)

	c2 := Computer2{}
	d2 := NewDirector(&c2)
	fmt.Printf("%+v\n", c2)
	d2.Construct()
	fmt.Printf("%+v\n", c2)
}
/*
{cpu: gpu:}
{cpu:intel gpu:nvida}
{cpu: gpu:}
{cpu:amd gpu:amd}
*/
```

## 原型模式

原型模式使对象能复制自身，并且暴露到接口中，使客户端面向接口编程时，不知道接口实际对象的情况下生成新的对象。

原型模式配合原型管理器使用，使得客户端在不知道具体类的情况下，通过接口管理器得到新的实例，并且包含部分预设定配置。

```go
package main

//Cloneable 是原型对象需要实现的接口
type Cloneable interface {
	Clone() Cloneable
}

type PrototypeManager struct {
	prototypes map[string]Cloneable
}

func NewPrototypeManager() *PrototypeManager {
	return &PrototypeManager{
		prototypes: make(map[string]Cloneable),
	}
}

func (p *PrototypeManager) Get(name string) Cloneable {
	return p.prototypes[name].Clone()
}

func (p *PrototypeManager) Set(name string, prototype Cloneable) {
	p.prototypes[name] = prototype
}
```



## References

https://github.com/senghoo/golang-design-pattern

https://refactoringguru.cn/design-patterns

https://lailin.xyz/post/singleton.html
