###from unicorn import * —— 加载主Unicorn库，它包含函数和基本Constant。
###from unicorn.x86_const import * —— 加载特定于x86和x86-64架构的Constant。
###Unicorn模块中的所有Const如下：
```
UC_API_MAJOR                UC_ERR_VERSION              UC_MEM_READ                 UC_PROT_ALL
UC_API_MINOR                UC_ERR_WRITE_PROT           UC_MEM_READ_AFTER           UC_PROT_EXEC
UC_ARCH_ARM                 UC_ERR_WRITE_UNALIGNED      UC_MEM_READ_PROT            UC_PROT_NONE
UC_ARCH_ARM64               UC_ERR_WRITE_UNMAPPED       UC_MEM_READ_UNMAPPED        UC_PROT_READ
UC_ARCH_M68K                UC_HOOK_BLOCK               UC_MEM_WRITE                UC_PROT_WRITE
UC_ARCH_MAX                 UC_HOOK_CODE                UC_MEM_WRITE_PROT           UC_QUERY_MODE
UC_ARCH_MIPS                UC_HOOK_INSN                UC_MEM_WRITE_UNMAPPED       UC_QUERY_PAGE_SIZE
UC_ARCH_PPC                 UC_HOOK_INTR                UC_MILISECOND_SCALE         UC_SECOND_SCALE
UC_ARCH_SPARC               UC_HOOK_MEM_FETCH           UC_MODE_16                  UC_VERSION_EXTRA
UC_ARCH_X86                 UC_HOOK_MEM_FETCH_INVALID   UC_MODE_32                  UC_VERSION_MAJOR
UC_ERR_ARCH                 UC_HOOK_MEM_FETCH_PROT      UC_MODE_64                  UC_VERSION_MINOR
UC_ERR_ARG                  UC_HOOK_MEM_FETCH_UNMAPPED  UC_MODE_ARM                 Uc
UC_ERR_EXCEPTION            UC_HOOK_MEM_INVALID         UC_MODE_BIG_ENDIAN          UcError
UC_ERR_FETCH_PROT           UC_HOOK_MEM_PROT            UC_MODE_LITTLE_ENDIAN       arm64_const
UC_ERR_FETCH_UNALIGNED      UC_HOOK_MEM_READ            UC_MODE_MCLASS              arm_const
UC_ERR_FETCH_UNMAPPED       UC_HOOK_MEM_READ_AFTER      UC_MODE_MICRO               debug
UC_ERR_HANDLE               UC_HOOK_MEM_READ_INVALID    UC_MODE_MIPS3               m68k_const
UC_ERR_HOOK                 UC_HOOK_MEM_READ_PROT       UC_MODE_MIPS32              mips_const
UC_ERR_HOOK_EXIST           UC_HOOK_MEM_READ_UNMAPPED   UC_MODE_MIPS32R6            sparc_const
UC_ERR_INSN_INVALID         UC_HOOK_MEM_UNMAPPED        UC_MODE_MIPS64              uc_arch_supported
UC_ERR_MAP                  UC_HOOK_MEM_VALID           UC_MODE_PPC32               uc_version
UC_ERR_MODE                 UC_HOOK_MEM_WRITE           UC_MODE_PPC64               unicorn
UC_ERR_NOMEM                UC_HOOK_MEM_WRITE_INVALID   UC_MODE_QPX                 unicorn_const
UC_ERR_OK                   UC_HOOK_MEM_WRITE_PROT      UC_MODE_SPARC32             version_bind
UC_ERR_READ_PROT            UC_HOOK_MEM_WRITE_UNMAPPED  UC_MODE_SPARC64             x86_const
UC_ERR_READ_UNALIGNED       UC_MEM_FETCH                UC_MODE_THUMB               
UC_ERR_READ_UNMAPPED        UC_MEM_FETCH_PROT           UC_MODE_V8                  
UC_ERR_RESOURCE             UC_MEM_FETCH_UNMAPPED       UC_MODE_V9
```


###来自unicorn.x86_const的一些Constant示例：
```
UC_X86_REG_EAX
UC_X86_REG_RIP
UC_X86_REG_RAX
mu = Uc(arch, mode) —— 获得一个Uc类的实例，在这里可以指定架构。
```

##举例来说：
```
mu = Uc(UC_ARCH_X86, UC_MODE_64) //获得一个x86-64架构的Uc实例。
mu = Uc(UC_ARCH_X86, UC_MODE_32) //获得一个x86-32架构的Uc实例。
mu.mem_map(ADDRESS, 4096) 映射一个内存区域。
mu.mem_write(ADDRESS, DATA) 将数据写入内存。
tmp = mu.mem_read(ADDRESS, SIZE) 从内存中读取数据。
mu.reg_write(UC_X86_REG_ECX, 0x0) 将寄存器重新赋值。
r_esp = mu.reg_read(UC_X86_REG_ESP) 读取寄存器的值。
mu.emu_start(ADDRESS_START, ADDRESS_END) 开始模拟。
```
###指令跟踪：
```
def hook_code(mu, address, size, user_data):  
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))  

mu.hook_add(UC_HOOK_CODE, hook_code)
```

这段代码添加了一个钩子。我们定义了函数hook_code，在模拟每个指令之前调用，该函数需要以下参数：
1、Uc实例
2、指令的地址
3、指令的大小
4、用户数据（我们可以在hook_add()的可选参数中传递这个值）
