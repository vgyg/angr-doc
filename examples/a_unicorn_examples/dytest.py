
# Press the green button in the gutter to run the script.
from unicorn import *
from unicorn.arm_const import *
import struct

ADDRESS = 0xb6bd7000
ARM_CODE   = "\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3
THUMB_CODE = "\x83\xb0" # sub    sp, #0xc

if __name__ == '__main__':
    # 创建uc对象
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    # 从内存中dump下来so的基址
    # 用来存放so代码的大小，尽量大一点。内存不值钱
    mem_size = 8 * 0x1000 * 0x1000
    # 创建一块内存
    mu.mem_map(ADDRESS, mem_size)
    # 在上面那块内存后面继续划一片内存来当做栈空间
    stack_addr = ADDRESS + mem_size
    stack_size = stack_addr
    mu.mem_map(stack_addr, stack_size)
    mu.mem_write(ADDRESS,ARM_CODE)
    mu.reg_write(UC_ARM_REG_R0,)
    mu.reg_write(UC_ARM_REG_R2, 0x6789)
    mu.reg_write(UC_ARM_REG_R3, 0x3333)
    mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    print(">>> R0 = 0x%x" %r0)
    print(">>> R1 = 0x%x" %r1)

    with open("libmetasec_ml.so_0xb6bd7000_0x94000.so", "rb") as f:
        sodata = f.read()
        # 给前面创建的空间写入so的数据
        mu.mem_write(code_addr, sodata)
        # 要执行的代码开始位置
        start_addr = code_addr + 0xfd8d
        # 要执行的代码结束位置
        end_addr = code_addr + 0xFDAA
        # 随机生成一个入参
        # 将生成的入参写入前面创建的内存空间
        # ida中看到的函数有参数1、2，然后分别对应X0和X1，写入对应数据，栈寄存器给一个栈顶的地址
        uc.reg_write(UC_ARM_REG_, args_addr)
        uc.reg_write(unicorn.arm64_const)
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_X1, len(input_str))
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_top)
        uc.mem_write(stack_top+4,p32(16777217))
        uc.mem_write(stack_top+8,p32(0))
        uc.mem_write(stack_top+12,p32(0))
        uc.mem_write(stack_top+16,input_str)
        uc.mem_write(stack_top+20,p32(0))
        # 开始执行代码段
        uc.emu_start(start_addr, end_addr)
        # ida中看到返回值是直接写在入参中，所以结果我们直接从入参的内存中读取
        result = uc.mem_read(args_addr, args_size)
        print("result:", result.decode(encoding="utf-8"))
    # 最后释放创建的内存
    uc.mem_unmap(args_addr, args_size)
    uc.mem_unmap(stack_addr, stack_size)
    uc.mem_unmap(code_addr, code_size)