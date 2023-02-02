---
title: "项目目录结构"
date: 2022-01-02T17:03:34+08:00
draft: false
toc: true
categories: [go]
tags: [golang,DDD]
authors:
    - haiyux
---

## 什么是DDD？

**DDD 是 Domain-Driven Design 的缩写。** 其主要的思想是，我们在设计软件时，先从业务出发，理解真实的业务含义，将业务中的一些概念吸收到软件建模中来，避免造出“大而无用”软件。也避免软件设计没有内在联系，否则一团散沙，无法继续演进。

## 为什么要使用DDD？

过去，最常用的架构是三层架构，最典型的是MVC。三层架构的问题就是控制层依赖业务层，业务层又依赖数据层。特别是在数据层为贫血模型下，会让业务层的代码高速膨胀。在维护过程中，改了一点需求就会引发意想不到的bug，修复bug又会引起其他的bug。

## 贫血模型和充血模型

贫血模型

所谓贫血模型，是指Model 中，仅包含状态(属性），不包含行为(方法），采用这种设计时，需要分离出DB层，专门用于数据库操作。

充血模型

Model 中既包括状态，又包括行为，是最符合面向对象的设计方式。

## 业务层设计

我们在写业务代码的时候，最终要的往往在业务层，控制层就是最一些参数校验处理，数据层就是持久化数据。业务逻辑集中在业务层，在三层就够中业务层往往依赖数据层，吧orm的model对象拿到业务层使用，这是出bug概率最大的问题。那我们能不能做出设计，在业务层，既不依赖控制层也不依赖数据层呢？

我们使用反向依赖的方式，让数据层依赖业务层。

比如我们要查询一些用户的订单信息

```go
type User struct {
    Id int 
    Name string
    Password string
    Age uint8
}

type Order struct {
    Id int
    Good string
    PayTime time.Time
}

type UserRepo interface {
    GetUsers(ctx context.Context,name string) ([]*User,error)
}

type OrderRepo interface {
    GetOrders(ctx context.Context,userId int) ([]*Order,error)
}

type UserUseCase struct {
    ur UserRepo
    or OrderRepo
}

func NewUserUseCase(ur UserRepo,or OrderRepo) *UserUseCase {
    return &UserUseCase{
        ur:ur,
        or:or,
    }
}

func (uuc *UserUseCase) GetOrders(ctx context.Context,name string) ([]*Order,error) {
    users,err := uuc.ur.GetUsers(ctx,name)
    if err != nil || len(users) == 0 {
        return fmt.Errorf("xxx%w",err)
    }
    userId := users[0].Id
    return uuc.or.GetOrders(ctx,userId)
}
```

在上面的例子中，在`GetOrders`方法中调用接口Repos中的方法，把业务代码写完之后，进行单元测试我们只要mock实现各个repo的接口就好。然后再持久层（数据层）实现这些repo方法，在方法中把PO转成DO。在控制层使用NewUserUseCase创建UseCase。进行调用吧DO转化成DTO返回。

当然在业务复杂时，usecase的方法要简单，吧逻辑都封装到domain service中。

## DTO DO和PO

DTO: Data Transfer Object的缩写。用于表示一个数据传输对象。DTO 通常用于不同服务或服务不同分层之间的数据传输。

BO: Business Object 的缩写,用于表示一个业务对象。

PO: Persistant Object缩写。用于数据库中一条记录映射成struct。

## 项目例子

项目例子可以查看 [beer-shop](https://github.com/go-kratos/beer-shop/) 项目，它是基于微服务框架[kratos](https://github.com/go-kratos/kratos) 实现的微服务项目。
