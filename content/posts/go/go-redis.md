---
title: "Go操作redis"
date: 2021-01-01T17:36:55+08:00
draft: false
toc: true
categories: [go,cache]
tags: [golang,redis]
authors:
    - haiyux
---


## 安装

下载第三方包:

```bash
go get -u github.com/go-redis/redis/v9
```

## 连接

```go
// 定义一个rdis客户端
var redisdb *redis.Client
// 初始化
func initClient() (err error) {
	redisdb = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // post端口
		Password: "", // 密码
		DB:       0,  // 使用redis的库
	})
	_, err = redisdb.Ping(context.Background()).Result()
	if err != nil {
		fmt.Println("连接失败")
		return
	}
	return
}
```

## 使用

### set/get示例

```go
func redisExample() {
	ctx := context.Background()
	err := redisdb.Set(ctx, "score", 100, 0).Err()
	if err != nil {
		fmt.Printf("set score failed, err:%v\n", err)
		return
	}
	val, err := redisdb.Get(ctx, "score").Result()
	if err != nil {
		fmt.Printf("get score failed, err:%v\n", err)
		return
	}
	fmt.Println("score", val)
	val2, err := redisdb.Get(ctx, "name").Result()
	if err == redis.Nil {
		fmt.Println("name does not exist")
	} else if err != nil {
		fmt.Printf("get name failed, err:%v\n", err)
		return
	} else {
		fmt.Println("name", val2)
	}
}
```

### zset示例

```go
func redisExample2() {
	ctx := context.Background()
	zsetKey := "language_rank"
	languages := []*redis.Z{
		&redis.Z{Score: 90.0, Member: "Golang"},
		&redis.Z{Score: 98.0, Member: "Java"},
		&redis.Z{Score: 95.0, Member: "Python"},
		&redis.Z{Score: 97.0, Member: "JavaScript"},
		&redis.Z{Score: 99.0, Member: "C/C++"},
	}
	// ZADD
	num, err := redisdb.ZAdd(ctx, zsetKey, languages...).Result()
	if err != nil {
		fmt.Printf("zadd failed, err:%v\n", err)
		return
	}
	fmt.Printf("zadd %d succ.\n", num)
	// 把Golang的分数加10
	newScore, err := redisdb.ZIncrBy(ctx, zsetKey, 10.0, "Golang").Result()
	if err != nil {
		fmt.Printf("zincrby failed, err:%v\n", err)
		return
	}
	fmt.Printf("Golang's score is %f now.\n", newScore)
	// 取分数最高的3个
	ret, err := redisdb.ZRevRangeWithScores(ctx, zsetKey, 0, 2).Result()
	if err != nil {
		fmt.Printf("zrevrange failed, err:%v\n", err)
		return
	}
	for _, z := range ret {
		fmt.Println(z.Member, z.Score)
	}
	// 取95~100分的
	op := &redis.ZRangeBy{
		Min: "95",
		Max: "100",
	}
	ret, err = redisdb.ZRangeByScoreWithScores(ctx, zsetKey, op).Result()
	if err != nil {
		fmt.Printf("zrangebyscore failed, err:%v\n", err)
		return
	}
	for _, z := range ret {
		fmt.Println(z.Member, z.Score)
	}
}
```

输出结果如下：

```bash
$ ./06redis_demo 
zadd 0 succ.
Golang's score is 100.000000 now.
Golang 100
C/C++ 99
Java 98
JavaScript 97
Java 98
C/C++ 99
Golang 100
```