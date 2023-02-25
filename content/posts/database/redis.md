---
title: "reids基础"
date: 2020-10-10T06:33:45+08:00
draft: false
toc: true
categories: [database]
tags: [redis]
authors:
    - haiyux
---

## redis介绍

Redis 是完全开源的，遵守 BSD 协议，是一个高性能的 key-value 数据库。

Redis 与其他 key - value 缓存产品有以下三个特点：

- Redis支持数据的持久化，可以将内存中的数据保存在磁盘中，重启的时候可以再次加载进行使用。
- Redis不仅仅支持简单的key-value类型的数据，同时还提供list，set，zset，hash等数据结构的存储。
- Redis支持数据的备份，即master-slave模式的数据备份。

### redis的安装

```bash
brew install redis(mac)
yum install redis(centos)
apt-get install redis(ubuntu)
```

## redis的命令网站

[Redis 命令参考 — Redis 命令参考 (redisfans.com)](http://doc.redisfans.com/)

## redis的基本操作

### redis的五大数据类型

redis的五大数据类型是: **String(字符串)、Hash(哈希)、List(列表)、Set(集合)、和zset(sorted set:有序集合)**

### redis键操作

- `keys *`查看当前库所有key   (匹配：keys *1)
- `exists key`判断某个key是否存在
- `type key` 查看你的key是什么类型
- `del key`    删除指定的key数据
- `unlink key`  根据value选择非阻塞删除   仅将keys从keyspace元数据中删除，真正的删除会在后续异步操作。
- `expire key 10 ` 10秒钟：为给定的key设置过期时间
- `ttl key` 查看还有多少秒过期，-1表示永不过期，-2表示已过期 
- `select`命令切换数据库
- `dbsize`查看当前数据库的key的数量
- `flushdb`清空当前库
- `flushall`通杀全部库

### 字符串(String)

#### 简介

String是Redis最基本的类型，你可以理解成与Memcached一模一样的类型，一个key对应一个value。

String类型是二进制安全的。意味着Redis的string可以包含任何数据。比如jpg图片或者序列化的对象。

String类型是Redis最基本的数据类型，一个Redis中字符串value最多可以是512M

#### 常用命令

- `set  <key><value>`添加键值对
- `get  <key>`查询对应键值
- `append  <key><value>`将给定的<value> 追加到原值的末尾
- `strlen  <key>`获得值的长度
- `setnx  <key><value>`只有在 key 不存在时   设置 key 的值
- `incr  <key>  `将 key 中储存的数字值增1 只能对数字值操作，如果为空，新增值为1
- `decr  <key>` 将 key 中储存的数字值减1  只能对数字值操作，如果为空，新增值为-1
- `incrby / decrby  <key><步长>`将 key 中储存的数字值增减。自定义步长。

#### 数据结构

String的数据结构为简单动态字符串(Simple Dynamic String,缩写SDS)。是可以修改的字符串，内部结构实现上类似于Java的ArrayList，采用预分配冗余空间的方式来减少内存的频繁分配.

![](/images/2344773-20210822104121617-1543511327.png)

如图中所示，内部为当前字符串实际分配的空间capacity一般要高于实际字符串长度len。当字符串长度小于1M时，扩容都是加倍现有的空间，如果超过1M，扩容时一次只会多扩1M的空间。需要注意的是字符串最大长度为512M。

### 列表(List)

#### 简介

单键多值

Redis 列表是简单的字符串列表，按照插入顺序排序。你可以添加一个元素到列表的头部（左边）或者尾部（右边）。

它的底层实际是个双向链表，对两端的操作性能很高，通过索引下标的操作中间的节点性能会较差。

![](/images/2344773-20210822104142657-469194505.png)

#### 常用命令

- `lpush/rpush  <key><value1><value2><value3> ....` 从左边/右边插入一个或多个值。
- `lpop/rpop  <key>`从左边/右边吐出一个值。值在键在，值光键亡。
- `rpoplpush  <key1><key2>`从<key1>列表右边吐出一个值，插到<key2>列表左边。
- `lrange <key><start><stop>`  按照索引下标获得元素(从左到右)
- `lrange mylist 0 -1`  0左边第一个，-1右边第一个，（0-1表示获取所有）
- `lindex <key><index>`按照索引下标获得元素(从左到右)
- `llen <key>`获得列表长度 
- `linsert <key>  before <value><newvalue>`在<value>的后面插入<newvalue>插入值
- `lrem <key><n><value>`从左边删除n个value(从左到右)
- `lset<key><index><value>`将列表key下标为index的值替换成value

#### 数据结构

List的数据结构为快速链表quickList。

首先在列表元素较少的情况下会使用一块连续的内存存储，这个结构是ziplist，也即是压缩列表。它将所有的元素紧挨着一起存储，分配的是一块连续的内存。当数据量比较多的时候才会改成quicklist。因为普通的链表需要的附加指针空间太大，会比较浪费空间。比如这个列表里存的只是int类型的数据，结构上还需要两个额外的指针prev和next。

![](/images/2344773-20210822104154068-1490126321.png)

Redis将链表和ziplist结合起来组成了quicklist。也就是将多个ziplist使用双向指针串起来使用。这样既满足了快速的插入删除性能，又不会出现太大的空间冗余。

### 集合(Set)

#### 简介

Redis set对外提供的功能与list类似是一个列表的功能，特殊之处在于set是可以***\*自动排重\****的，当你需要存储一个列表数据，又不希望出现重复数据时，set是一个很好的选择，并且set提供了判断某个成员是否在一个set集合内的重要接口，这个也是list所不能提供的。

Redis的Set是string类型的无序集合。它底层其实是一个value为null的hash表，所以添加，删除，查找的***\*复杂度都是O(1)\****。

一个算法，随着数据的增加，执行时间的长短，如果是O(1)，数据增加，查找数据的时间不变

#### 常用命令

- `sadd <key><value1><value2> ..... `将一个或多个 member 元素加入到集合 key 中，已经存在的 member 元素将被忽略
- `smembers <key>`取出该集合的所有值。
- `sismember <key><value>`判断集合<key>是否为含有该<value>值，有1，没有0
- `scard<key>`返回该集合的元素个数。
- `srem <key><value1><value2> ....` 删除集合中的某个元素。
- `spop <key>`***\*随机从该集合中吐出一个值。\****
- `srandmember <key><n>`随机从该集合中取出n个值。不会从集合中删除 。
- `smove <source><destination>`value把集合中一个值从一个集合移动到另一个集合
- `sinter <key1><key2>`返回两个集合的交集元素。
- `sunion <key1><key2>`返回两个集合的并集元素。
- `sdiff <key1><key2>`返回两个集合的***\*差集\****元素(key1中的，不包含key2中的)

#### 数据结构

Set数据结构是dict字典，字典是用哈希表实现的。
Java中HashSet的内部实现使用的是HashMap，只不过所有的value都指向同一个对象。Redis的set结构也是一样，它的内部也使用hash结构，所有的value都指向同一个内部值。

### 哈希(Hash)

#### 简介

Redis hash 是一个键值对集合。

Redis hash是一个string类型的field和value的映射表，hash特别适合用于存储对象。

#### 常用命令

- `hset <key><field><value>`给<key>集合中的  <field>键赋值<value>
- `hget <key1><field>`从<key1>集合<field>取出 value 
- `hmset <key1><field1><value1><field2><value2>... `批量设置hash的值
- `hexists<key1><field>`查看哈希表 key 中，给定域 field 是否存在。 
- `hkeys <key>`列出该hash集合的所有field
- `hvals <key>`列出该hash集合的所有value
- `hincrby <key><field><increment>`为哈希表 key 中的域 field 的值加上增量 1  -1
- `hsetnx <key><field><value>`将哈希表 key 中的域 field 的值设置为 value ，当且仅当域 field 不存在 .

#### 数据结构

Hash类型对应的数据结构是两种：ziplist（压缩列表），hashtable（哈希表）。当field-value长度较短且个数较少时，使用ziplist，否则使用hashtable。

### 有序集合Zset(sorted set)

#### 简介

Redis有序集合zset与普通集合set非常相似，是一个没有重复元素的字符串集合。

不同之处是有序集合的每个成员都关联了一个***\*评分（score）\****,这个评分（score）被用来按照从最低分到最高分的方式排序集合中的成员。集合的成员是唯一的，但是评分可以是重复了 。

因为元素是有序的, 所以你也可以很快的根据评分（score）或者次序（position）来获取一个范围的元素。

访问有序集合的中间元素也是非常快的,因此你能够使用有序集合作为一个没有重复成员的智能列表。

#### 常用命令

- `zadd  <key><score1><value1><score2><value2>… `将一个或多个 member 元素及其 score 值加入到有序集 key 当中。
- `zrange <key><start><stop>  [WITHSCORES] `   返回有序集 key 中，下标在<start><stop>之间的元素带WITHSCORES，可以让分数一起和值返回到结果集。
- `zrangebyscore key minmax [withscores] [limit offset count]` 返回有序集 key 中，所有 score 值介于 min 和 max 之间(包括等于 min 或 max )的成员。有序集成员按 score 值递增(从小到大)次序排列。 
- `zrevrangebyscore key maxmin [withscores] [limit offset count] `         同上，改为从大到小排列。 
- `zincrby <key><increment><value>`    为元素的score加上增量
- `zrem  <key><value>`删除该集合下，指定值的元素 
- `zcount <key><min><max>`统计该集合，分数区间内的元素个数 
- `zrank <key><value>`返回该值在集合中的排名，从0开始。

#### 数据结构

SortedSet(zset)是Redis提供的一个非常特别的数据结构，一方面它等价于Java的数据结构Map<String, Double>，可以给每一个元素value赋予一个权重score，另一方面它又类似于TreeSet，内部的元素会按照权重score进行排序，可以得到每个元素的名次，还可以通过score的范围来获取元素的列表。

zset底层使用了两个数据结构

1. hash，hash的作用就是关联元素value和权重score，保障元素value的唯一性，可以通过元素value找到相应的score值。
2. 跳跃表，跳跃表的目的在于给元素value排序，根据score的范围获取元素列表。

## Redis新数据类型

### Bitmaps

#### 简介

现代计算机用二进制（位） 作为信息的基础单位， 1个字节等于8位， 例如“abc”字符串是由3个字节组成， 但实际在计算机存储时将其用二进制表示， “abc”分别对应的ASCII码分别是97、 98、 99， 对应的二进制分别是01100001、 01100010和01100011，如下图

![](/images/2344773-20210822104217377-993547167.png)

合理地使用操作位能够有效地提高内存使用率和开发效率。

Redis提供了Bitmaps这个“数据类型”可以实现对位的操作：

1. Bitmaps本身不是一种数据类型， 实际上它就是字符串（key-value） ， 但是它可以对字符串的位进行操作。
2. Bitmaps单独提供了一套命令， 所以在Redis中使用Bitmaps和使用字符串的方法不太相同。 可以把Bitmaps想象成一个以位为单位的数组， 数组的每个单元只能存储0和1， 数组的下标在Bitmaps中叫做偏移量。

![](/images/2344773-20210822104229331-33955654.png)

#### 命令

1. setbit

（1）格式

`setbit<key><offset><value>`设置Bitmaps中某个偏移量的值（0或1）

![](/images/2344773-20210822104240133-810682231.png)

*offset:偏移量从0开始 

（2）实例

每个独立用户是否访问过网站存放在Bitmaps中， 将访问的用户记做1， 没有访问的用户记做0， 用偏移量作为用户的id。

设置键的第offset个位的值（从0算起） ， 假设现在有20个用户，userid=1， 6， 11， 15， 19的用户对网站进行了访问， 那么当前Bitmaps初始化结果如图

![](/images/2344773-20210822104254299-1643973179.png)

unique:users:20201106代表2020-11-06这天的独立访问用户的Bitmaps

![](/images/2344773-20210822104303999-1626642786.png)

注：

很多应用的用户id以一个指定数字（例如10000） 开头， 直接将用户id和Bitmaps的偏移量对应势必会造成一定的浪费， 通常的做法是每次做setbit操作时将用户id减去这个指定数字。

在第一次初始化Bitmaps时， 假如偏移量非常大， 那么整个初始化过程执行会比较慢， 可能会造成Redis的阻塞。

2. getbit

（1）格式
getbit<key><offset>获取Bitmaps中某个偏移量的值

获取键的第offset位的值（从0开始算）

（2）实例
获取id=8的用户是否在2020-11-06这天访问过， 返回0说明没有访问过

![](/images/2344773-20210822104318020-1492153741.png)

注：因为100根本不存在，所以也是返回0

3. bitcount

统计字符串被设置为1的bit数。一般情况下，给定的整个字符串都会被进行计数，通过指定额外的 start 或 end 参数，可以让计数只在特定的位上进行。start 和 end 参数的设置，都可以使用负数值：比如 -1 表示最后一个位，而 -2 表示倒数第二个位，start、end 是指bit组的字节的下标数，二者皆包含。
（1）格式
bitcount<key>[start end] 统计字符串从start字节到end字节比特值为1的数量


（2）实例
计算2022-11-06这天的独立访问用户数量

start和end代表起始和结束字节数， 下面操作计算用户id在第1个字节到第3个字节之间的独立访问用户数， 对应的用户id是11， 15， 19。

```
举例： K1 【01000001 01000000  00000000 00100001】，对应【0，1，2，3】
bitcount K1 1 2  ： 统计下标1、2字节组中bit=1的个数，即01000000  00000000
--》bitcount K1 1 2 　　--》1

bitcount K1 1 3  ： 统计下标1、2字节组中bit=1的个数，即01000000  00000000 00100001
--》bitcount K1 1 3　　--》3

bitcount K1 0 -2  ： 统计下标0到下标倒数第2，字节组中bit=1的个数，即01000001  01000000   00000000
--》bitcount K1 0 -2　　--》3
```

 注意：redis的setbit设置或清除的是bit位置，而bitcount计算的是byte位置。

4. bitop

(1)格式
bitop  and(or/not/xor) <destkey> [key…]

![](/images/2344773-20210822104347550-1602906251.png)

bitop是一个复合操作， 它可以做多个Bitmaps的and（交集） 、 or（并集） 、 not（非） 、 xor（异或） 操作并将结果保存在destkey中。

 

(2)实例

2020-11-04 日访问网站的userid=1,2,5,9。

setbit unique:users:20201104 1 1

setbit unique:users:20201104 2 1

setbit unique:users:20201104 5 1

setbit unique:users:20201104 9 1

 

 

 

2020-11-03 日访问网站的userid=0,1,4,9。

setbit unique:users:20201103 0 1

setbit unique:users:20201103 1 1

setbit unique:users:20201103 4 1

setbit unique:users:20201103 9 1

 

计算出两天都访问过网站的用户数量

bitop and unique:users:and:20201104_03

unique:users:20201103unique:users:20201104

![](/images/2344773-20210822104409205-112998705.png) 

![](/images/2344773-20210822104423561-1297650702.png)

计算出任意一天都访问过网站的用户数量（例如月活跃就是类似这种） ， 可以使用or求并集

![](/images/2344773-20210822104435961-48187161.png)

#### Bitmaps与set对比

假设网站有1亿用户， 每天独立访问的用户有5千万， 如果每天用集合类型和Bitmaps分别存储活跃用户可以得到表

| set和Bitmaps存储一天活跃用户对比 |                    |                  |                        |
| -------------------------------- | ------------------ | ---------------- | ---------------------- |
| 数据类型                         | 每个用户id占用空间 | 需要存储的用户量 | 全部内存量             |
| 集合类型                         | 64位               | 50000000         | 64位*50000000 = 400MB  |
| Bitmaps                          | 1位                | 100000000        | 1位*100000000 = 12.5MB |

很明显， 这种情况下使用Bitmaps能节省很多的内存空间， 尤其是随着时间推移节省的内存还是非常可观的

| set和Bitmaps存储独立用户空间对比 |        |        |       |
| -------------------------------- | ------ | ------ | ----- |
| 数据类型                         | 一天   | 一个月 | 一年  |
| 集合类型                         | 400MB  | 12GB   | 144GB |
| Bitmaps                          | 12.5MB | 375MB  | 4.5GB |

但Bitmaps并不是万金油， 假如该网站每天的独立访问用户很少， 例如只有10万（大量的僵尸用户） ， 那么两者的对比如下表所示， 很显然， 这时候使用Bitmaps就不太合适了， 因为基本上大部分位都是0。

| set和Bitmaps存储一天活跃用户对比（独立用户比较少） |                    |                  |                        |
| -------------------------------------------------- | ------------------ | ---------------- | ---------------------- |
| 数据类型                                           | 每个userid占用空间 | 需要存储的用户量 | 全部内存量             |
| 集合类型                                           | 64位               | 100000           | 64位*100000 = 800KB    |
| Bitmaps                                            | 1位                | 100000000        | 1位*100000000 = 12.5MB |

### HyperLogLog

#### 简介

在工作当中，我们经常会遇到与统计相关的功能需求，比如统计网站PV（PageView页面访问量）,可以使用Redis的incr、incrby轻松实现。
但像UV（UniqueVisitor，独立访客）、独立IP数、搜索记录数等需要去重和计数的问题如何解决？这种求集合中不重复元素个数的问题称为基数问题。
解决基数问题有很多种方案：
（1）数据存储在MySQL表中，使用distinct count计算不重复个数

（2）使用Redis提供的hash、set、bitmaps等数据结构来处理

以上的方案结果精确，但随着数据不断增加，导致占用空间越来越大，对于非常大的数据集是不切实际的。

能否能够降低一定的精度来平衡存储空间？Redis推出了HyperLogLog

Redis HyperLogLog 是用来做基数统计的算法，HyperLogLog 的优点是，在输入元素的数量或者体积非常非常大时，计算基数所需的空间总是固定的、并且是很小的。

在 Redis 里面，每个 HyperLogLog 键只需要花费 12 KB 内存，就可以计算接近 2^64 个不同元素的基数。这和计算基数时，元素越多耗费内存就越多的集合形成鲜明对比。

但是，因为 HyperLogLog 只会根据输入元素来计算基数，而不会储存输入元素本身，所以 HyperLogLog 不能像集合那样，返回输入的各个元素。

什么是基数?

比如数据集 {1, 3, 5, 7, 5, 7, 8}， 那么这个数据集的基数集为 {1, 3, 5 ,7, 8}, 基数(不重复元素)为5。 基数估计就是在误差可接受的范围内，快速计算基数。

#### 命令

1、pfadd 

（1）格式

pfadd <key>< element> [element ...]  添加指定元素到 HyperLogLog 中

![](/images/2344773-20210822104453962-1987702553.png)

（2）实例

![](/images/2344773-20210822104511571-1054685663.png)

	将所有元素添加到指定HyperLogLog数据结构中。如果执行命令后HLL估计的近似基数发生变化，则返回1，否则返回0。

2、pfcount

（1）格式

pfcount<key> [key ...] 计算HLL的近似基数，可以计算多个HLL，比如用HLL存储每天的UV，计算一周的UV可以使用7天的UV合并计算即可

![](/images/2344773-20210822104523019-1060895308.png)

（2）实例

![](/images/2344773-20210822104557594-209731117.png)

3、pfmerge

（1）格式

pfmerge<destkey><sourcekey> [sourcekey ...]  将一个或多个HLL合并后的结果存储在另一个HLL中，比如每月活跃用户可以使用每天的活跃用户来合并计算可得

![](/images/2344773-20210822104657581-1072488082.png)

（2）实例

![](/images/2344773-20210822104708122-225764470.png)

###  Geospatial

#### 简介

Redis 3.2 中增加了对GEO类型的支持。GEO，Geographic，地理信息的缩写。该类型，就是元素的2维坐标，在地图上就是经纬度。redis基于该类型，提供了经纬度设置，查询，范围查询，距离查询，经纬度Hash等常见操作。

#### 命令

1、geoadd 

（1）格式

geoadd<key>< longitude><latitude><member> [longitude latitude member...]  添加地理位置（经度，纬度，名称）

![](/images/2344773-20210822104721907-2118360636.png)

2）实例

geoadd china:city 121.47 31.23 shanghai

geoadd china:city 106.50 29.53 chongqing 114.05 22.52 shenzhen 116.38 39.90 beijing 

![](/images/2344773-20210822104736859-685047335.png)

两极无法直接添加，一般会下载城市数据，直接通过 Java 程序一次性导入。

有效的经度从 -180 度到 180 度。有效的纬度从 -85.05112878 度到 85.05112878 度。

当坐标位置超出指定范围时，该命令将会返回一个错误。

已经添加的数据，是无法再次往里面添加的。

2、geopos  

（1）格式

geopos  <key><member> [member...]  获得指定地区的坐标值

![](/images/2344773-20210822104753243-512291139.png)

（2）实例

![](/images/2344773-20210822104802897-75505679.png)

3、geodist 

（1）格式

geodist<key><member1><member2>  [m|km|ft|mi ]  获取两个位置之间的直线距离

![](/images/2344773-20210822104816935-1672928435.png)

（2）实例

获取两个位置之间的直线距离

![](/images/2344773-20210822104826840-448574183.png)

单位：

m 表示单位为米[默认值]。 

 km 表示单位为千米。

mi 表示单位为英里。

ft 表示单位为英尺。

如果用户没有显式地指定单位参数， 那么 GEODIST 默认使用米作为单位 

4、georadius

（1）格式

georadius<key>< longitude><latitude>radius m|km|ft|mi  以给定的经纬度为中心，找出某一半径内的元素

![](/images/2344773-20210822104839952-1368013784.png)

经度 纬度 距离 单位 

（2）实例

![](/images/2344773-20210822104848997-1956452627.png)
