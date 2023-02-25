---
title: "Go文件系统"
date: 2019-02-11T15:36:17+08:00
draft: false
toc: true
categories: [go]
tags: [golang]
authors:
    - haiyux
---

## 检测文件是否存在

```go
//存在返回 true，不存在返回 false
func fileIfExist(filename string) bool {
    _, err := os.Stat(filename)
    if nil != err {
        fmt.Println(filename, "is not exist!")
        return false
    }

    if os.IsNotExist(err) {
        return false
    }

    return true
}
```

## 打开文件

```go
f, err := os.Open(filename)
if nil != err {
    fmt.Println("open", filename, "failed!")
    return
}
defer f.Close()
```

如果文件不存在，就会返回错误，如果存在就以只读的方式打开文件。

还可以使用 `os.OpenFile()` 打开文件，达到不存在就新建，存在就清空（`os.O_TRUNC`）的目的。当然，也可以不清空文件（`os.O_APPEND`）。

```go
f, err := os.OpenFile(filename, os.O_RDWR | os.O_CREATE | os.O_TRUNC, 0666)
if nil != err {
    fmt.Println("create", filename, "failed!")    
    return
}
defer f.Close()
```

## 新建文件

```go
f, err := os.Create(filename)
if nil != err {
    fmt.Println("create", filename, "failed!")
    return
}
defer f.Close()
```

注意：如果文件已经存在，那么 `os.Create()` 会将文件清空。可以使用 `os.OpenFile()` 新建文件， 参数 `flag` 为 `os.O_CREATE | os.O_EXCL`。如果文件已经存在，那么该函数就会返回错误。

```go
f, err := os.OpenFile(filename, os.O_CREATE | os.O_EXCL, 0666)
if nil != err {
    fmt.Println("create", filename, "failed!")    
    return
}
defer f.Close()
```

## 读取文件

### 读取全部内容

```go
content := make([]byte, 1024)   //需要预先分配空间
f, _ := os.Open(filename)
defer f.Close()
_, err := f.Read(content)
if nil != err {
    fmt.Println("read", filename, "failed!")
    return
}
```

读取文件内容可以使用 `File` 的方法——`Read`。但是使用该方法时需要预先分配空间，用于存储读取的文件内容。我们当然可以提前获取文件的大小，但是这种方式仍然不如 `ioutil.ReadAll()` 方便。甚至可以直接使用 `ioutil.ReadFile()`。

`ioutil.ReadAll()`：

```go
f, _ := os.Open(filename)
defer f.Close()
content, err := ioutil.ReadAll(f)
if nil != err {
    fmt.Println("read", filename, "failed!")
    return
}
fmt.Println(string(content))
```

`ioutil.ReadFile()`：

```go
content, err := ioutil.ReadFile(filename)
if nil != err {
    fmt.Println("read", filename, "failed!")
    return
}
fmt.Println(string(content))
```

### 按行读取

```go
f, _ := os.Open(filename)
defer f.Close()
scanner := bufio.NewScanner(f) //按行读取
for scanner.Scan() {
    fmt.Println(scanner.Text()) //输出文件内容
}
```

## 写入文件

```go
f, _ := os.OpenFile(filename, os.O_WRONLY | os.O_APPEND, 0666)
defer f.Close()
_, err = f.WriteString("target_compile_option")
if nil != err {
    fmt.Println(err)
}
```

这里使用 `os.OpenFile()` 以追加的方式打开文件。为什么不使用 `os.Open()` 打开文件呢？因为 `os.Open()` 是以只读的方式打开文件，无法向文件写入数据。

我们也可以使用 `ioutil.WriteFile()` 写文件。

```go
writeContent := "write file test"
err = ioutil.WriteFile(filename, []byte(writeContent), os.ModePerm)
if nil != err {
    fmt.Println("write", filename, "failed!")
}
```

注意：使用 `ioutil.WriteFile(filename string, data []byte, perm os.FileMode)` 向文件中写入时，如果文件存在，文件会先被清空，然后再写入。如果文件不存在，就会以 `perm` 权限先创建文件，然后再写入。

## 关闭文件

直接调用 `File` 的 `Close()` 方法。

```go
f, _ := os.Open(filename)
f.Close()
```

最好使用 `defer` 关键字执行 `Close()` 方法，这样能够保证函数退出时文件能被关闭。

## 删除文件

```go
err := os.Remove(filename)
```

删除文件前确保文件没有被其他程序使用。如果在当前程序中该文件已被打开，需要先关闭（`Close()`）文件。
