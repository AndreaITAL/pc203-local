import struct, loader
from unicorn import *
from unicorn.arm_const import *

L=loader.Lib()
S=L.syms
SETKEY   = S['_ZN15VIDEO_SEC_DEDES10DES_SetKeyEPc']
DEC8     = S['_ZN15VIDEO_SEC_DEDES13DES_Decrypt_8EPhS0_i']
DEC64    = S['_ZN15VIDEO_SEC_DEDES14DES_Decrypt_64EPhS0_i']
DECBLOCK = S['_ZN15VIDEO_SEC_DEDES16DES_DecryptBlockEyPy']
MAKESUB  = S['_ZN15VIDEO_SEC_DEDES18DES_MakeSubKeys_64Ey']

STACK=0x70010000; STACKSZ=0x100000
SCRATCH=0x80000000
THIS=SCRATCH; KEY=SCRATCH+0x4000; SRC=SCRATCH+0x5000; DST=SCRATCH+0x6000
RET=0x70000000
KEYBYTES=bytes([0x33,0x44,0x33,0x30,0x36,0x51,0x44,0x54])  # 3D306QDT

def new_uc():
    uc=Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    L.map_into(uc)
    uc.mem_map(STACK-STACKSZ, STACKSZ, UC_PROT_ALL)
    uc.mem_map(SCRATCH, 0x10000, UC_PROT_ALL)
    def hook_code(uc,addr,size,ud):
        if 0x90000000<=addr<0x90001000:
            name=L.externs.get(addr,'?')
            r0=uc.reg_read(UC_ARM_REG_R0); r1=uc.reg_read(UC_ARM_REG_R1); r2=uc.reg_read(UC_ARM_REG_R2)
            if 'memcpy' in name or 'memmove' in name:
                uc.mem_write(r0, bytes(uc.mem_read(r1,r2))); uc.reg_write(UC_ARM_REG_R0,r0)
            elif 'memset' in name:
                uc.mem_write(r0, bytes([r1&0xff])*r2); uc.reg_write(UC_ARM_REG_R0,r0)
            else:
                raise Exception('extern non gestito: '+name)
            lr=uc.reg_read(UC_ARM_REG_LR); uc.reg_write(UC_ARM_REG_PC,lr)
    uc.hook_add(UC_HOOK_CODE, hook_code, begin=0x90000000, end=0x90001000)
    return uc

def call(uc, addr, r0=0,r1=0,r2=0,r3=0, stack=()):
    uc.reg_write(UC_ARM_REG_R0,r0); uc.reg_write(UC_ARM_REG_R1,r1)
    uc.reg_write(UC_ARM_REG_R2,r2); uc.reg_write(UC_ARM_REG_R3,r3)
    sp=(STACK-0x80) & ~7
    if stack:
        need=4*len(stack)
        sp=(sp-need)&~7
        for i,v in enumerate(stack): uc.mem_write(sp+4*i, struct.pack('<I',v&0xffffffff))
    uc.reg_write(UC_ARM_REG_SP,sp)
    uc.reg_write(UC_ARM_REG_LR, RET|1)
    cpsr=uc.reg_read(UC_ARM_REG_CPSR)|0x20
    uc.reg_write(UC_ARM_REG_CPSR,cpsr)
    uc.emu_start((addr&~1)|1, RET, count=500000)
    return (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1))

def setkey(uc, key8=KEYBYTES):
    uc.mem_write(KEY, key8)
    call(uc, SETKEY, r0=THIS, r1=KEY)
