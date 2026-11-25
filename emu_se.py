"""
emu_se — esegue pw_seEncryption dalla libreria originale della camera
(libpwnativenetsdk.so) tramite un piccolo emulatore ARM (Unicorn).

pw_seEncryption(char* in1, char* in2, char* out, int len):
  - calcola un digest MD5 e lo formatta in una stringa base32hex da 20 caratteri
  - usato a stadi per derivare le chiavi DES della camera

Richiede: unicorn, pyelftools  e  lib_so/libpwnativenetsdk.so (estratta dalla
propria app IPC360). loader.py deve stare nella stessa cartella.
"""
import loader
from unicorn import *
from unicorn.arm_const import *

L = loader.Lib()
SE = 0x1c5e50                       # offset di pw_seEncryption nella .so (thumb)
STACK = 0x70010000; STACKSZ = 0x100000
SCRATCH = 0x80000000; RET = 0x70000000
HEAP = 0xa0000000; HEAPSZ = 0x200000
IN1 = SCRATCH + 0x200; IN2 = SCRATCH + 0x400; OUT = SCRATCH + 0x600


def _mkuc():
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    L.map_into(uc)
    uc.mem_map(STACK - STACKSZ, STACKSZ, UC_PROT_ALL)
    uc.mem_map(SCRATCH, 0x10000, UC_PROT_ALL)
    uc.mem_map(HEAP, HEAPSZ, UC_PROT_ALL)
    uc.reg_write(UC_ARM_REG_C1_C0_2, uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xf << 20))  # VFP
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    st = {'brk': HEAP + 0x100}

    def hook_code(uc, addr, size, ud):
        if 0x90000000 <= addr < 0x90001000:        # chiamate a funzioni esterne (libc)
            name = L.externs.get(addr, '?')
            r0 = uc.reg_read(UC_ARM_REG_R0); r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2); ret = 0
            if name == 'malloc':
                sz = (r0 + 15) & ~15; ret = st['brk']; st['brk'] += sz if sz else 16
            elif name in ('free', '_ZdlPv', 'operator delete'):
                ret = 0
            elif name in ('memcpy', 'memmove', '__aeabi_memcpy', '__aeabi_memcpy4', '__aeabi_memcpy8'):
                uc.mem_write(r0, bytes(uc.mem_read(r1, r2))); ret = r0
            elif name in ('memset', '__aeabi_memset', '__aeabi_memclr'):
                uc.mem_write(r0, bytes([r1 & 0xff]) * r2); ret = r0
            elif name == 'strlen':
                ret = bytes(uc.mem_read(r0, 256)).split(b'\x00')[0].__len__()
            elif name == '__stack_chk_fail':
                raise Exception("STACK_CHK_FAIL")
            else:
                raise Exception("extern non gestito: " + name + f" @{addr:#x}")
            uc.reg_write(UC_ARM_REG_R0, ret)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_code, begin=0x90000000, end=0x90001000)
    return uc, st


def se(in1, in2, outlen=0x24):
    """pw_seEncryption(in1, in2) -> stringa di 20 caratteri."""
    uc, st = _mkuc()
    uc.mem_write(IN1, in1.encode() + b'\x00')
    uc.mem_write(IN2, in2.encode() + b'\x00')
    uc.mem_write(OUT, b'\x00' * 0x80)
    uc.reg_write(UC_ARM_REG_R0, IN1); uc.reg_write(UC_ARM_REG_R1, IN2)
    uc.reg_write(UC_ARM_REG_R2, OUT); uc.reg_write(UC_ARM_REG_R3, outlen)
    sp = (STACK - 0x80) & ~7
    uc.reg_write(UC_ARM_REG_SP, sp); uc.reg_write(UC_ARM_REG_LR, RET | 1)
    uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
    uc.emu_start(SE | 1, RET, count=10000000)
    return bytes(uc.mem_read(OUT, 0x40)).split(b'\x00')[0].decode('latin1')
