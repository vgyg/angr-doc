# Press the green button in the gutter to run the script.
import struct
from unicorn import *
from unicorn.arm_const import *
import unicorn

import inspect
import itertools
import logging

from unicorn.x86_const import UC_X86_REG_RIP

logger = logging.getLogger(__name__)


class JavaClassDef(type):
    next_jvm_id = itertools.count(start=1)
    next_jvm_method_id = itertools.count(start=0xd2000000, step=4)
    next_jvm_field_id = itertools.count(start=0xe2000000, step=4)

    def __init__(cls, name, base, ns, jvm_name=None, jvm_fields=None, jvm_ignore=False, jvm_super=None):
        cls.jvm_id = next(JavaClassDef.next_jvm_id)
        cls.jvm_name = jvm_name
        cls.jvm_methods = dict()
        cls.jvm_fields = dict()
        cls.jvm_ignore = jvm_ignore
        cls.jvm_super = jvm_super

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], 'jvm_method'):
                method = func[1].jvm_method
                method.jvm_id = next(JavaClassDef.next_jvm_method_id)
                cls.jvm_methods[method.jvm_id] = method

        # Register all defined Java fields.
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                jvm_field.jvm_id = next(JavaClassDef.next_jvm_field_id)
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field

        type.__init__(cls, name, base, ns)

    def __new__(mcs, name, base, ns, **kargs):
        return type.__new__(mcs, name, base, ns)

    def register_native(self, name, signature, ptr_func):
        found = False
        found_method = None

        # Search for a defined jvm method.
        for method in self.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            x = "Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__)
            logger.warning(x)
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, self.__name__))
        logger.debug("Registered native function ('%s', '%s') to %s.%s" % (name, signature,
                                                                           self.__name__, found_method.func_name))

    def find_method(cls, name, signature):
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method

        return None

    def find_method_by_id(cls, jvm_id):
        return cls.jvm_methods[jvm_id]

    def find_field(cls, name, signature, is_static):
        for field in cls.jvm_fields.values():
            if field.name == name and field.signature == signature and field.is_static == is_static:
                return field

        return None

    def find_field_by_id(cls, jvm_id):
        try:
            if cls.jvm_super is not None:
                return cls.jvm_super.find_field_by_id(jvm_id)
        except KeyError:
            pass

        return cls.jvm_fields[jvm_id]


def native_translate_arg(emu, val):
    if isinstance(val, int):
        print("int")
        return val
    elif isinstance(val, str):
        print("str")
        return jstring(val)
    elif isinstance(val, list):
        print("list")
        return jobjectArray(val)
    elif isinstance(val, bytearray):
        print("bytearray")
        return jbyteArray(val)
    elif isinstance(type(val), JavaClassDef):
        print("JavaClassDef")
        # TODO: Look into this, seems wrong..
        return jobject(val)
    elif isinstance(val, JavaClassDef):
        print("JavaClassDef")
        return jclass(val)
    else:
        raise NotImplementedError("Unable to write response '%s' type '%s' to emulator." % (str(val), type(val)))


class jvalue:

    def __init__(self, value=None):
        self.value = value


class jobject:

    def __init__(self, value=None):
        self.value = value


class jclass(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jstring(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jarray(jobject):

    def __init__(self, value=None):
        super().__init__(value)


class jobjectArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jbooleanArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jbyteArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jcharArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jshortArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jintArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jlongArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jfloatArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jdoubleArray(jarray):

    def __init__(self, value=None):
        super().__init__(value)


class jthrowable(jobject):

    def __init__(self, value=None):
        super().__init__(value)


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


instructions_skip_list = [0xb6be6d8e, 0xb6be6d90, 0x0000000000400502, 0x000000000040054F]


def hook_code(mu, address, size, user_data):
    instruction = mu.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
    print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))
    if address in instructions_skip_list:
        print('skip')
        mu.reg_write(UC_X86_REG_RIP, address + 14)

    # for x in mu.mem_read(address, size):
    #     print(hex(x))


if __name__ == '__main__':
    # 从内存中dump下来so的基址
    code_addr = 0xb6bd7000
    # 创建uc对象
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    # 从内存中dump下来so的基址
    # 用来存放so代码的大小，尽量大一点。内存不值钱
    mem_size = 8 * 1024 * 1024
    # 创建一块内存
    mu.mem_map(code_addr, mem_size)
    # 在上面那块内存后面继续划一片内存来当做栈空间
    stack_addr = code_addr + mem_size
    stack_size = stack_addr
    # 栈顶的位置，这里是64位的，所以偏移8个字节
    stack_top = stack_addr + stack_size
    mu.mem_map(stack_addr, stack_size)
    # 栈空间往后继续划一块空间用来存放参数
    args_addr = stack_addr + stack_size
    args_size = 0x1000
    mu.mem_map(args_addr, args_size)
    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    with open("libmetasec_ml.so_0xb6bd7000_0x94000.so", "rb") as f:
        sodata = f.read()
        # 给前面创建的空间写入so的数据
        mu.mem_write(code_addr, sodata)
        # 要执行的代码开始位置
        start_addr = code_addr + 0xfd8d
        # 要执行的代码结束位置
        end_addr = code_addr + 0xFDAA
        # 将生成的入参写入前面创建的内存空间

        # Object result = jniDispatchTest64.a(16777217, 0, 0, "cfb6b9", new byte[]{122, 112, 5, 82});
        mu.reg_write(UC_ARM_REG_R0, 16777217)
        mu.reg_write(UC_ARM_REG_R1, 0)
        mu.reg_write(UC_ARM_REG_R2, 0)
        input_str = "cfb6b9"
        input_byte = str.encode(input_str)
        mu.mem_write(args_addr, input_byte)
        mu.reg_write(UC_ARM_REG_R3, args_addr)
        res = mu.mem_read(args_addr,len(input_byte))
        print('res:',res)
        # input_byte1=[122, 112, 5, 82]
        # mu.mem_write(args_addr,input_byte1)
        mu.reg_write(UC_ARM_REG_R4, args_addr)
        mu.reg_write(UC_ARM_REG_R5, args_addr)
        mu.reg_write(UC_ARM_REG_R6, args_addr)

        mu.reg_write(UC_ARM_REG_R7, args_addr)

        mu.reg_write(UC_ARM_REG_R12, args_addr)
        # mu.reg_write(UC_ARM_REG_SP, args_addr)
        # 开始执行代码段
        try:
            res = mu.emu_start(start_addr, end_addr)
            print("res: ", res)
        except UcError as e:
            print("ERROR: %s" % e)

        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        pc = mu.reg_read(UC_ARM_REG_PC)
        sp = mu.reg_read(UC_ARM_REG_SP)
        print(">>> R0 = 0x%x" % r0)
        print(">>> R1 = 0x%x" % r1)
        print(">>> R2 = 0x%x" % mu.reg_read(UC_ARM_REG_R2))
        print(">>> R3 = 0x%x" % mu.reg_read(UC_ARM_REG_R3))
        # 最后释放创建的内存
    mu.mem_unmap(args_addr, args_size)
    mu.mem_unmap(stack_addr, stack_size)
    mu.mem_unmap(code_addr, mem_size)
