---
title: "Go复杂数据结构"
date: 2019-01-28T20:38:18+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---


## 数组

**数组是一个由固定长度的特定类型元素组成的序列，一个数组可以由零个或多个元素组成。** 因为数组的长度是固定的，因此在Go语言中很少直接使用数组。

数组的每个元素可以通过索引下标来访问，索引下标的范围是从0开始到数组长度减1的位置。内置的len函数将返回数组中元素的个数。

```go
var a [3]int             // 长度为3的数组
fmt.Println(a[0])        // 打印第一个数据
fmt.Println(a[len(a)-1]) // 打印最后一个数据
for i, v := range a {
    fmt.Printf("%d %d\n", i, v) // 循环数组 i为索引 v为数据
}
```

**默认情况下，数组的每个元素都被初始化为元素类型对应的零值**

数组的初始化:

```go
var a [3]int = [3]int{1, 2, 3}
b := [...]int{1, 2, 3}
a = [4]int{1, 2, 3, 4} // panic 数据初始化就是定长了  长度不能变化
```

## 切片

Slice（切片）代表变长的序列，序列中每个元素都有相同的类型。一个slice类型一般写作[]T，其中T代表slice中元素的类型；slice的语法和数组很像，只是没有固定长度而已。

**一个slice由三个部分构成：指针、长度和容量**。指针指向第一个slice元素对应的底层数组元素的地址，要注意的是slice的第一个元素并不一定就是数组的第一个元素。长度对应slice中元素的数目；长度不能超过容量，容量一般是从slice的开始位置到底层数据的结尾位置。内置的len和cap函数分别返回slice的长度和容量。

多个slice之间可以共享底层的数据，并且引用的数组部分区间可能重叠。

**使用make()函数构造切片**

```go
make([]T, size, cap)   // T:切片类型  size 切片数量  cap 切片容量
```

**append()方法为切片添加元素**

```go
sli := make([]int,0,10)
sli = append(sli,1)	 // 添加一个 1
arr := [4]int{6,7,8,9}
sli = append(sle,arr...) // 把arr打散并全部添加  添加多个
fmt.Println(sli)    // [1 6 7 8 9]
```

**从切片中删除元素**

```go
// 从切片中删除元素
a := []int{30, 31, 32, 33, 34, 35, 36, 37}
// 要删除索引为2的元素
a = append(a[:2], a[3:]...)
fmt.Println(a) //[30 31 33 34 35 36 37]
```

**切片的扩容策略**

```go
func growslice(et *_type, old slice, cap int) slice {
	newcap := old.cap
	doublecap := newcap + newcap
	if cap > doublecap {
		newcap = cap
	} else {
		if old.len < 1024 {
			newcap = doublecap
		} else {
			for 0 < newcap && newcap < cap {
				newcap += newcap / 4
			}
			if newcap <= 0 {
				newcap = cap
			}
		}
	}
```

在分配内存空间之前需要先确定新的切片容量，Go 语言根据切片的当前容量选择不同的策略进行扩容：

1.  如果期望容量大于当前容量的两倍就会使用期望容量；
2.  如果当前切片容量小于 1024 就会将容量翻倍；
3.  如果当前切片容量大于 1024 就会每次增加 25% 的容量，直到新容量大于期望容量；

## MAP

哈希表是一种巧妙并且实用的数据结构。它是一个**无序的key/value对的集合**，其中所有的key都是不同的，然后通过给定的key可以在常数时间复杂度内检索、更新或删除对应的value。在Go语言中，一个map就是一个哈希表的引用，map类型可以写为map[K]V，其中K和V分别对应key和value。

*   初始化:

```go
m := make(map[string]int)
```

*   赋值初始化

```go
m := map[string]int{
    "zhy":   18,
    "who": 30,
}
// 直接赋值相当于
ages := make(map[string]int)
ages["zhy"] = 18
ages["who"] = 30
```

**Map的迭代顺序是不确定的，并且不同的哈希函数实现可能导致不同的遍历顺序。**遍历的顺序是随机的，每一次遍历的顺序都不相同。

如果要有序:

```go
// 用sort进项排序
var names []string
for name := range ages {
    names = append(names, name)
}
sort.Strings(names)
for _, name := range names {
    fmt.Printf("%s\t%d\n", name, ages[name])
}
```

## 结构体

**结构体是一种聚合的数据类型，是由零个或多个任意类型的值聚合成的实体。每个值称为结构体的成员。**

```go
type people struct {
    name string
    age uint8
    hobby []string
    address string 
    sex uint8
}
var zhy people
```

**结构体赋值**

```go
h := []string{"唱","跳","RAP","篮球"}
zhy := people{"zhaohaiyu",18,h,"地球",1}
```

或者

```go
var zhy people
zhy.name = "zhaohaiyu"
zhy.age = 18
zhy.hobby = h
zhy.address = "地球"
zhy.sex = 1
```

### 结构体比较

如果结构体的全部成员都是可以比较的，那么结构体也是可以比较的，那样的话两个结构体将可以使用或!=运算符进行比较。相等比较运算符将比较两个结构体的每个成员，因此下面两个比较的表达式是等价的：

```go
type Point struct{ X, Y int }
p := Point{1, 2}
q := Point{2, 1}
fmt.Println(p.X == q.X && p.Y == q.Y) // "false"
fmt.Println(p == q)                   // "false"
```

### 结构体的继承

在java,python,cpp等语言中都有类的继承的概念,go语言中没有类.用结构体的嵌套实现继承.

```go
type animal struct {
    name string
    age int
}
type people struct {
    address string
    animal animal
}
var zhy = people{
    address: "地球",
    animal:  animal{
        name: "zhaohaiyu",
        age:  18,
    },
}
fmt.Println(zhy.animal)  // {zhaohaiyu 18}
fmt.Println(zhy.animal.name) // zhaohaiyu
fmt.Println(zhy.animal.age)  // 18
fmt.Println(zhy.address) //地球
```

## JSON

JSON(JavaScript Object Notation, JS 对象简谱) 是一种轻量级的数据交换格式。它基于ECMAScript(欧洲计算机协会制定的js规范)的一个子集，采用完全独立于编程语言的文本格式来存储和表示数据。简洁和清晰的层次结构使得 JSON 成为理想的数据交换语言。 易于人阅读和编写，同时也易于机器解析和生成，并有效地提升网络传输效率。

Go语言对于这些标准格式的编码和解码都有良好的支持，由标准库中的**encoding/json**包提供支持

JSON是对JavaScript中各种类型的值——字符串、数字、布尔值和对象——Unicode本文编码。它可以用有效可读的方式表示第三章的基础数据类型和本章的数组、slice、结构体和map等聚合数据类型。

*   各类型的json数据

```go
boolean         true
number          -273.15
string          "hello world!!!!"
array           ["i", "you", "her"]
object          {"year": 2020,
                 "event":"huawei","American virus","Trump is crazy"}
```

*   go语言结构体成员Tag来指定对应的JSON名字。同样，在解码的时候也需要做同样的处理

```go
type People struct {
    Name string `json:"name"`
    Age int `json:"age"`
    PhoneNumber string `json:"phone_number"`
}
```

*   要将结构体的数据发给游览器前端或者安卓,IOS,APP等进行展示,因为go语言首字母小写只能本包用,在外部包要首字母大写,包括结构体和结构体成员.而且go语言崇尚驼峰体命名,而很多语言崇尚下划线命名.所有我们要用tag把json数据的成员变成首字母小写以及下划线命名.