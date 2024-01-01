# Socket-To-Socket

加数网络数据

## 编译

```bash
make gen
```

## 加载

```bash
make run
```

## 测试

- 运行服务器

```bash
$ nc -l 5001
```

- 运行客服端

```bash
$ nc 127.0.0.1  5001
# 运行后写入数据
test
```

- 抓包

```bash
$ tcpdump -i lo port 5001
# 可以看到只有 握手和挥手消息,中间传输数据消息都没有了
```







