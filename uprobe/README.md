# Uprobe

> 用户态跟踪

用户态空间跟踪使用 **uprobe** 和 **用户空间定义的静态跟踪点**（User Statically Defined Tracing，简称 USDT）。

和内核一个问题，要想进行跟踪需要先找到跟踪点，一般来说，我们找跟踪点是从二进制文件中查找。在有调试信息的情况下，就可以通过 [readdlf](https://man7.org/linux/man-pages/man1/readelf.1.html) 、[objdump](https://man7.org/linux/man-pages/man1/objdump.1.html) 、[nm](https://man7.org/linux/man-pages/man1/nm.1.html) 等工具查询可用于跟踪的函数、变量等符号列表。比如查询加解密的 [openssl 动态库](https://cppget.org/libssl)

```bash
# 查询符号表（RHEL8系统中请把动态库路径替换为/usr/lib64/libssl.so）
readelf -Ws /usr/lib/x86_64-linux-gnu/libssl.so

# 查询USDT信息（USDT信息位于ELF文件的notes段）
readelf -n /usr/lib/x86_64-linux-gnu/libssl.so
```

或者使用 bpftrace 工具。

```bash
# 查询uprobe（RHEL8系统中请把动态库路径替换为/usr/lib64/libssl.so）
bpftrace -l 'uprobe:/usr/lib/x86_64-linux-gnu/libssl.so:*'

# 查询USDT
bpftrace -l 'usdt:/usr/lib/x86_64-linux-gnu/libssl.so:*'
```

## 编程语言对追踪的影响

常用的编程语言按照运行原理，大致可以分为三类;

- 第一类是 C、C++、Golang 等编译为机器码后再执行的**编译型语言**。这类语言通常会被编译成 ELF 格式的二进制文件，包含了保存在寄存器或栈中的函数参数和返回值，因此可以直接通过二进制文件中的符号进行跟踪。
- 第二类是 Python、Bash、Ruby 等通过解释器语法分析之后的**解释型语言**。这类编程语言开发的程序，无法直接从语言运行时的二进制文件中获取应用程序的调试信息，通常需要跟踪解释器的函数，再从其参数中获取应用程序的运行细节。
- 第三类是 Java、.Net、JavaScript 等先编译为字节码，再有即时编译器（JIT）编译为机器码执行的**即时编译型语言**。同解释型语言类似，这类编程语言无法直接从语言运行的二进制文件中获取应用程序的调试信息，跟踪 JIT 编程语言开发的程序最为困难，因为 JIT 编译的状态只存在于内存中。通常需要一个 [map-agent](https://github.com/jvm-profiling-tools/perf-map-agent) 的东西



## Reference

https://kiosk007.top/post/%E5%A6%82%E4%BD%95%E4%BD%BF%E7%94%A8ebpf%E8%BF%9B%E8%A1%8C%E8%BF%BD%E8%B8%AA/#%E4%BD%BF%E7%94%A8-libbpf-%E6%96%B9%E6%B3%95%E8%BF%9B%E8%A1%8C%E8%B7%9F%E8%B8%AA

https://www.hi-roy.com/posts/ebpf%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B03/

https://www.zhihu.com/column/c_1477442442325012480