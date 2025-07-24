# coding 

## 编码前准备流程
1. 明确需要使用的 kprobe/tracepoint 点，不能使用非 probe/tracepoint 的函数, 支持的 kprobe && tracepoint 点直接在测试环境主机上获取，亦可参考 kprobe_functions.txt；
2. 定义需要输出到 userspace 的数据结构, 并且划分 kernel && userspace 需要处理的流程；
3. 设计 ebpf 部分处理流程; 
4. 设计 userspace 部分 python 代码流程；
5. 实现

## 代码风格 && 实现详情
### bcc 代码 总体原则：
1. bcc 代码默认使用 c && python 混合单个文件编写的方式。
2. python 部分使用 python2 兼容写法，保证不同运行环境可用。
3. python 打印行不应当包含特殊符号。


### bcc python 部分
1. bcc 代码 python 版本导入以及导入 package 方式如下，保证使用不同的 bcc 包版本都能正常导入（python-bcc/python3-bpfcc）。
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither 'bcc' nor 'bpfcc' module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
```


### bcc c 代码部分

1. 需要考虑 bpf stack 限制，对于数据部分使用可扩展性更好的 map 类型；
2. 目标机器普遍未开启 btf，无法使用 CORE 框架，使用底层 bpf 命令直接读写内存；
3. 代码所需的 kernel （或 userspace 程序）数据结构导入：1）优先使用在 header 中导入包含数据结构完整定义 header 文件的形式；
    2）如果无法直接导入 header file，则在代码中写入数据结构定义，基本原则为：写入的数据结构定义中需要包含 c 代码中需要引用的数据结构字段前的所有字段，需要引用的字段后的字段可以 padding；
   kernel 代码参考 kernel-source/kernel 