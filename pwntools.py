from pwn import *
from ctypes import *
from LibcSearcher import *
from collections import OrderedDict
import os, re, sys, time, signal, string, hashlib, warnings, subprocess


class Environ(OrderedDict):
    """
    Environ类, 用于生成pwnio对象, 可以进行赋值配置
    """

    def __getattr__(self, key):
        return self.__getitem__(key)

    def __setattr__(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        if key == "libc_base" and self.libc:
            return self.libc.address
        return super().__getitem__(key) if key in self.keys() else None

    def __setitem__(self, key, value):
        if key == "libc_base" and self.libc:
            self.libc.address = value
        else:
            return super().__setitem__(key, value)

    def __init__(self):
        self.elf = ELF(which("sh"), False)
        self.libc = ELF(which("sh"), False)
        self.io = None
        self.ip = ""
        self.port = 0
        self.debug = True
        self.show_warning = False
        self.timeout = 5
        self.terminal_args = [
            "cmd.exe",
            "/c",
            "wt.exe",
            "new-tab",
            "cmd.exe",
            "/c",
            "wsl.exe",
            "-e",
        ]
        self.filepath = ""
        self.start_args = []  # 启动process启动参数


arglen = len(sys.argv)
pwnio = Environ()


def init(path: str = "", ip: str = "", port: int = 0, start_args: list = []) -> None:
    """初始化

    :param path: elf文件路径
    :type path: str
    :param ip: 远程ip
    :type ip: str
    :param port: 远程端口
    :type port: int
    :param start_args: 启动参数
    :type start_args: list
    """
    global pwnio

    if arglen > 1:
        ip, port = (
            (sys.argv[1].split(":")[0], sys.argv[1].split(":")[1])
            if arglen == 2
            else (sys.argv[1], sys.argv[2])
        )

    if not path:
        path = pwnio.filepath

    if not path:
        raise ValueError("Choose your elf file path")

    if not pwnio.show_warning:
        warnings.filterwarnings("ignore")

    pwnio.elf = ELF(path)
    pwnio.filepath = pwnio.elf.path
    pwnio.libc = pwnio.elf.libc  # 如果是静态编译, libc就是 None

    if not pwnio.libc:
        info("Static ELF has no libc")

    if ip and port:
        pwnio.ip = ip
        pwnio.port = port

    if start_args:
        pwnio.start_args = start_args

    context.terminal = pwnio.terminal_args
    context.arch = pwnio.elf.arch

    if pwnio.timeout:
        context.timeout = pwnio.timeout

    pwnio.io = getprocess()


def ret2libc(addr: int, func: str, binary=None) -> tuple:
    """一键ret2libc, 返回system函数地址和/bin/sh\x00字符串地址

    :param addr: 地址的偏移
    :type addr: int
    :param func: 泄露的函数的地址名称
    :type func: str
    :param binary: libc的ELF类型, 为空使用LibcSearcher去寻找, defaults to None
    :type binary: _type_, optional
    :return: (system, binsh)
    :rtype: tupe
    """
    libc = LibcSearcher(func, addr) if not binary else binary
    libc.address = addr - libc.dump(func) if not binary else addr - libc.sym[func]
    if not binary:
        pwnio.libc_base = libc.address
    system = libc.address + libc.dump("system") if not binary else libc.sym["system"]
    binsh = (
        libc.address + libc.dump("str_bin_sh")
        if not binary
        else next(libc.search(b"/bin/sh\x00"))
    )
    info("libc_base", libc.address)
    info("system", system)
    info("binsh", binsh)
    return (system, binsh)


def get4hash(key: str, value: str, is_front=True) -> str:
    """获取sha256爆破的值

    :param key: key
    :type key: str
    :param value: value
    :type value: str
    :param is_front: key在前还是在后, defaults to True
    :type is_front: bool, optional
    :return: 长度为4的key
    :rtype: str
    """
    table = string.ascii_letters + string.digits
    for a in table:
        for b in table:
            for c in table:
                for d in table:
                    tk = (
                        (a + b + c + d + key) if is_front else (key + a + b + c + d)
                    ).encode()
                    if hashlib.sha256(tk).hexdigest() == value:
                        tk = a + b + c + d
                        info(f"hash key --> {tk}")
                        return tk
    return "wood"


def hack(pwn, time_sleep=0, cls=True) -> None:
    """对pwn函数进行无限次爆破, 直到成功

    :param pwn: 调用的pwn函数
    :type pwn: function
    :param time_sleep: 每次爆破的时间间隔, defaults to 0
    :type time_sleep: int, optional
    :param cls: 是否在每次调用pwn函数之后清空屏, defaults to True
    :type cls: bool, optional
    """
    times = 0
    while True:
        try:
            times += 1
            info(f"time --> {times}")
            pwn()
            if time_sleep:
                time.sleep(time_sleep)
        except:
            try:
                if pwnio.io:
                    pwnio.io.close()
            except:
                pass
            pwnio.io = getprocess()
            if cls:
                clear()


def get_clib(libc_path="") -> CDLL:
    """获取libc进行调用c原生函数

    :param libc_path: 需要调用的libc的路径, defaults to ""
    :type libc_path: str, optional
    :return: libc
    :rtype: libc
    """
    if not libc_path:
        return cdll.LoadLibrary(pwnio.libc.path)
    else:
        return cdll.LoadLibrary(libc_path)


def search_flag(data, flag_pre="flag") -> str:
    """搜索data中的flag

    :param data: 携带flag的数据
    :type data: bytes | str
    :param flag_pre: flag前缀, defaults to "flag"
    :type flag_pre: str, optional
    :return: flag
    :rtype: str
    """
    is_str = True
    if type(data) == bytes:
        # 如果是字节，尝试转为字符串
        is_str = False
        try:
            data = data.decode()
            is_str = True
        except:
            pass
    if is_str:
        tmp = re.search(flag_pre + r"{(.*?)}", data)
        return tmp.group() if tmp else ""
    else:
        tmp = re.search(flag_pre.encode() + r"{(.*?)}".encode(), data)
        return tmp.group().decode() if tmp else ""


def info(da1, da2=None) -> None:
    """输入一些信息

    :param da1: 函数名 | 想输出的信息
    :type da1: str
    :param da2: 函数地址, defaults to None
    :type da2: int, optional
    """
    if type(da1) == int and type(da2) == str:
        log.success(f"\033[33m{da2}\033[0m = \033[31m{da1:#x}\033[0m")
    elif type(da1) == int and da2 == None:
        log.success(f"\033[31m{da1:#x}\033[0m")
    elif type(da1) == str and type(da2) == int:
        log.success(f"\033[33m{da1}\033[0m = \033[31m{da2:#x}\033[0m")
    elif type(da1) == str and da2 == None:
        log.info(f"\033[36m{da1}\033[0m")
    else:
        log.info("\033[31m Can not understand it! \033[0m")


def close_dbg() -> None:
    """关闭debug"""
    pwnio.debug = False


def open_dbg() -> None:
    """开启debug"""
    pwnio.debug = True


def leak(address, name="leak_addr"):
    """
    打印某个泄露出来的地址
    """
    if type(address) != int:
        log.info("\033[31m Can not understand it! \033[0m")
        return 0
    info(name, address)
    return address


s = lambda data: pwnio.io.send(data)
"""
发送数据, 不换行
"""

sa = lambda rv, data: pwnio.io.sendafter(rv, data)
"""
在接收到某字符后发送, 不换行
"""

sl = lambda data: pwnio.io.sendline(data)
"""
发送一行
"""

sla = lambda rv, data: pwnio.io.sendlineafter(rv, data)
"""
在接收到某字符后发送, 换行
"""

r = lambda num=None: pwnio.io.recv(num) if num else pwnio.io.recv()
"""
接收num个字符
"""

rl = lambda keepends=False: pwnio.io.recvline(keepends)
"""
接收一行
"""

ra = lambda time=pwnio.timeout: pwnio.io.recvall(time)
"""
接收所有
"""

ru = (
    lambda data, drop=True, time=0: pwnio.io.recvuntil(data, drop)
    if not time
    else pwnio.io.recvuntil(data, drop, time)
)
"""
接收到某个东西为止
"""

ia = lambda: pwnio.io.interactive()
"""
交互
"""

l32 = lambda: u32(ru(b"\xf7", False)[-4:].ljust(4, b"\x00"))
"""
接收\xf7开头的32位数据
"""

l64 = lambda: u64(ru(b"\x7f", False)[-6:].ljust(8, b"\x00"))
"""
接收\x7f开头的64位数据
"""

uu32 = lambda data: u32(data.ljust(4, b"\x00"))
"""
转化32位的数据
"""

uu64 = lambda data: u64(data.ljust(8, b"\x00"))
"""
转化64位的数据
"""

i16 = lambda data: int(data, 16)
"""
字符串转为16进制
"""

i10 = lambda data: int(data, 10)
"""
转为10进制
"""

dbg = (
    lambda point=None: None
    if arglen > 1 or not pwnio.debug
    else (gdb.attach(pwnio.io) if not point else gdb.attach(pwnio.io, f"{point}"))
)
"""
使用gdb.attach的方式调试进程, 如果io是remote或debug=False不会开启
"""

og = (
    lambda path=None: list(
        map(
            int,
            subprocess.check_output(["one_gadget", "--raw", "-f", pwnio.libc.path])
            .decode()
            .strip("\n")
            .split(" "),
        )
    )
    if not path
    else list(
        map(
            int,
            subprocess.check_output(["one_gadget", "--raw", "-f", path])
            .decode()
            .strip("\n")
            .split(" "),
        )
    )
)
"""
一键获取one_gadget的所有地址, 返回一个携带地址的int list
"""

rg = lambda binary, only, grep: i16(
    subprocess.check_output(
        [f"ROPgadget --binary {binary} --only '{only}' | grep {grep}"], shell=True
    )
    .decode()
    .split(" ")[0]
)
"""
获取ROPgadget的结果
binary: ROPgadget的 --binary 参数
only: ROPgadget的 --only 参数
grep: 提取特定名称
"""

getprocess = (
    lambda: process(pwnio.start_args)
    if pwnio.start_args
    else (
        remote(pwnio.ip, pwnio.port)
        if pwnio.ip and pwnio.port
        else process(pwnio.filepath)
    )
)
"""获取一个进程, 通过启动python的参数判断是否进行remote
"""

clear = lambda: os.system("clear")
"""清空屏幕"""

pau = lambda: pause()
"""暂停"""

list_equally_split = lambda list_data, num: [
    list_data[i * num : (i + 1) * num]
    for i in range(int(len(list_data) / num) + 1)
    if list_data[i * num : (i + 1) * num]
]
"""
    小工具, 一行代码搞定列表均分
    list_data: 需要被分割的列表
    num: 每个列表的长度
"""


class timeout:
    """一个自定义执行时间的class, 超时就raise一个错误
    使用方法 with timeout(seconds=114514): print(114514)
    """

    def __init__(self, seconds=5, error_message="Timeout"):
        self.seconds = seconds
        self.error_message = error_message

    @staticmethod
    def handle_timeout(signum, frame):
        raise

    def __enter__(self):
        try:
            signal.signal(signal.SIGALRM, self.handle_timeout)
            signal.alarm(self.seconds)
        except:
            raise

    def __exit__(self, type, value, traceback):
        signal.alarm(0)
