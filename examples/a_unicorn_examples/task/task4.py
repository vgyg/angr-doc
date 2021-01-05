from unicorn import *
from unicorn.arm_const import *

import struct


def read(name):
    with open(name,"rb") as f:
        return f.read()


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)

BASE = 0x10000
STACK_ADDR = 0x300000
STACK_SIZE = 1024 * 1024

mu.mem_map(BASE, 1024 * 1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)

mu.mem_write(BASE, read("./task4"))
aa=STACK_ADDR + (int)(STACK_SIZE / 2)
mu.reg_write(UC_ARM_REG_SP,aa )

instructions_skip_list = []

CCC_ENTRY = 0x000104D0
CCC_END = 0x00010580

stack = []  # Stack for storing the arguments
d = {}  # Dictionary that holds return values for given function arguments


def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address == CCC_ENTRY:  # Are we at the beginning of ccc function?
        arg0 = mu.reg_read(UC_ARM_REG_R0)  # Read the first argument. it is passed by R0

        if arg0 in d:  # Check whether return value for this function is already saved.
            ret = d[arg0]
            mu.reg_write(UC_ARM_REG_R0, ret)  # Set return value in R0
            mu.reg_write(UC_ARM_REG_PC,
                         0x105BC)  # Set PC to point at "BX LR" instruction. We want to return from fibonacci function

        else:
            stack.append(arg0)  # If return value is not saved for this argument, add it to stack.

    elif address == CCC_END:
        arg0 = stack.pop()  # We know arguments when exiting the function

        ret = mu.reg_read(UC_ARM_REG_R0)  # Read the return value (R0)
        d[arg0] = ret  # Remember the return value for this argument


mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x00010584, 0x000105A8)

return_value = mu.reg_read(UC_ARM_REG_R1)  # We end the emulation at printf("%d\n", ccc(x)).
print("The return value is %d" % return_value)