---
title: "MySQL数据完整性约束"
date: 2020-01-15T10:33:45+08:00
draft: false
toc: true
categories: [database]
tags: [mysql]
authors:
    - haiyux
---



## 主键约束

主键可以是表中的某一列，也可以是表中的多个列所构成的一个组合；其中，由多个列组合而成的主键也称为复合主键。在MySQL中，主键列必须遵守以下规则。

（1）每一个表只能定义一个主键。

（2）唯一性原则。主键的值，也称键值，必须能够唯一表示表中的每一条记录，且不能为NULL。

（3）最小化规则。复合主键不能包含不必要的多余列。也就是说，当从一个复合主键中删除一列后，如果剩下的列构成的主键仍能满足唯一性原则，那么这个复合主键是不正确的。

（4）一个列名在复合主键的列表中只能出现一次。

示例：创建学生信息表tb_student时，将学号（stu_id）字段设置为主键。

```sql
CREATE TABLE tb_student
(
	stu_id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(30)
);
```

示例：创建用户信息表tb_student时，将学号（stu_id）和所在班级号（class_id）字段设置为复合主键。

```sql
CREATE TABLE tb_student
(
	stu_id INT AUTO_INCREMENT,
	name VARCHAR(30),
	class_id INT NOT NULL,
	PRIMARY KEY (stu_id,class_id)
);
```

示例：通过修改数据表结构，添加主键约束。

```sql
ALTER TABLE tb_student ADD CONSTRAINT PRIMARY KEY(stu_id);
```

## 唯一约束

唯一约束使用UNIQUE关键字来定义。唯一约束的值必须是唯一的，且不能为空（NULL）。

在MySQL中，唯一约束与主键之间存在以下两点区别。

（1）一个表只能创建一个主键，但可以定义多个唯一约束。

（2）定义主键约束时，系统会自动创建PRIMARY KEY索引，而定义候选键约束时，系统会自动创建UNIQUE索引。

示例：创建用户信息表tb_student时，将学号（stu_id）和姓名（name）设置为唯一约束。

```sql
CREATE TABLE tb_student
(
	stu_id INT UNIQUE,
	name VARCHAR(30) UNIQUE
);
```

示例：创建用户信息表tb_student时，将学号（stu_id）和姓名（name）字段设置为复合唯一约束。

```sql
CREATE TABLE tb_student
(
	stu_id INT,
	name VARCHAR(30),
	UNIQUE uniq_id_name (stu_id,name)
);
```

示例：通过修改数据表结构，添加唯一约束。

```sql
ALTER TABLE tb_student ADD CONSTRAINT uniq_id_name UNIQUE(stu_id,name);
```

## 外键约束

MySQL有两种常用的引擎类型（MyISAM和InnoDB），目前，只用InnoDB引擎类型支持外键约束。

示例：创建班级信息表（tb_class）和学生信息表（tb_student），并设置学生信息表中班级编号（class_id）字段的外键约束。

-- 创建班级信息表

```sql
CREATE TABLE tb_class
(
	class_id INT AUTO_INCREMENT PRIMARY KEY,
	class_name VARCHAR(30) NOT NULL
);
```

-- 创建学生信息表，并设置班级ID的外键约束

```sql
CREATE TABLE tb_student
(
	stu_id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(30),
	class_id INT NOT NULL,
	FOREIGN KEY fk_class_id (class_id)
	REFERENCES tb_class(class_id)
);
```


示例：通过修改数据表结构，添加外键约束。

```sql
ALTER TABLE tb_student ADD CONSTRAINT FOREIGN KEY fk_class_id (class_id) REFERENCES tb_class(class_id);
```

## 非空约束

非空约约束就是限制必须为某个列提供值。空值（NULL）是不存在值，它既不是数字0，也不是空字符串，而是不存在、未知的情况。

示例：创建学生信息表tb_student时，将姓名（name）字段添加为非空约束。

```sql
CREATE TABLE tb_student
(
	stu_id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(30) NOT NULL
);
```

示例：通过修改数据表结构，将姓名（name）字段修改为非空。

```sql
ALTER TABLE tb_student MODIFY COLUMN name VARCHAR(30) NOT NULL;
```

## 检查约束

检查约束用来指定某列的可取值的范围，它通过限制输入到列中的值来强制域的完整性。

示例：创建学生信息表tb_student时，将年龄（age）的值设置在7至18之间（不包括18）的数值。

```sql
CREATE TABLE tb_student
(
	stu_id INT AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(30),
	age INT NOT NULL CHECK(age>=7 AND age<18)
);
```

注意：目前的MySQL版本只是对CHECK约束进行了分析处理，但会被直接忽略，并不会报错。

## 约束的删除

删除约束语法：

```sql
ALTER TABLE 表名 DROP [FOREIGN KEY| INDEX 约束名称]|[PRIMARY KEY]
```

示例：删除约束。

```sql
CREATE TABLE tb_student
(
	stu_id INT,
	name VARCHAR(30) ,
	class_id INT NOT NULL,

-- 主键约束
PRIMARY KEY(stu_id),

-- 外键约束
FOREIGN KEY fk_class_id (class_id)
REFERENCES tb_class(class_id),

-- 唯一性约束
UNIQUE uniq_name (name)

);
-- 删除主键约束
ALTER TABLE tb_student DROP PRIMARY KEY;

-- 删除外键约束
ALTER TABLE tb_student DROP FOREIGN KEY fk_class_id;

-- 删除唯一性约束
ALTER TABLE tb_student DROP INDEX uniq_name;
```

## 文章转自：

https://blog.csdn.net/pan_junbiao/article/details/86158117
