from unicorn import *
from unicorn.x86_const import *
import struct


def read(name):
    with open(name,"rb") as f:
        return f.read()


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


mu = Uc(UC_ARCH_X86, UC_MODE_32)

BASE = 0x08048000
STACK_ADDR = 0x0
STACK_SIZE = 1024 * 1024

mu.mem_map(BASE, 1024 * 1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE, read("./function"))
r_esp = STACK_ADDR + (STACK_SIZE / 2)  # ESP points to this address at function call

STRING_ADDR = 0x0
mu.mem_write(STRING_ADDR,
             "batman\x00")  # write "batman" somewhere. We have choosen an address 0x0 which belongs to the stack.

mu.reg_write(UC_X86_REG_ESP, r_esp)  # set ESP
mu.mem_write(r_esp + 4, p32(5))  # set the first argument. It is integer 5
mu.mem_write(r_esp + 8, p32(STRING_ADDR))  # set the second argument. This is a pointer to the string "batman"

mu.emu_start(0x8048464, 0x804849A)  # start emulation from the beginning of super_function, end at RET instruction
return_value = mu.reg_read(UC_X86_REG_EAX)
print("The returned value is: %d" % return_value)