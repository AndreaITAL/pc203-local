import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import *
from unicorn.arm_const import *

SO='lib_so/libpwnativenetsdk.so'

class Lib:
    def __init__(self):
        self.f=open(SO,'rb'); self.e=ELFFile(self.f)
        self.syms={}
        for sn in ('.symtab','.dynsym'):
            s=self.e.get_section_by_name(sn)
            if s:
                for sym in s.iter_symbols():
                    if sym.name and sym['st_value']:
                        self.syms.setdefault(sym.name, sym['st_value'])
        # build memory image
        loads=[s for s in self.e.iter_segments() if s['p_type']=='PT_LOAD']
        self.minv=min(s['p_vaddr'] for s in loads)
        self.maxv=max(s['p_vaddr']+s['p_memsz'] for s in loads)
        self.base=0
        size=self.maxv
        self.img=bytearray(size)
        for s in loads:
            self.f.seek(s['p_offset'])
            d=self.f.read(s['p_filesz'])
            self.img[s['p_vaddr']:s['p_vaddr']+len(d)]=d
        self._apply_relocs()
    def _r32(self,a): return struct.unpack_from('<I',self.img,a)[0]
    def _w32(self,a,v): struct.pack_into('<I',self.img,a,v & 0xffffffff)
    def _apply_relocs(self):
        e=self.e
        self.externs={}  # sentinel addr -> name
        self.ext_by_name={}
        sent=0x90000000
        for sec in e.iter_sections():
            if not isinstance(sec, RelocationSection): continue
            symtab=e.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                off=r['r_offset']; t=r['r_info_type']; si=r['r_info_sym']
                sym=symtab.get_symbol(si) if si else None
                if t==23:  # R_ARM_RELATIVE: loc += base(0) -> unchanged
                    continue
                elif t in (21,22,2):  # GLOB_DAT, JUMP_SLOT, ABS32
                    if sym is not None and sym['st_value']:
                        val=sym['st_value']
                        if t==2:  # ABS32 in-place addend
                            val=(sym['st_value']+self._r32(off))
                        self._w32(off,val)
                    else:
                        nm=sym.name if sym else '?'
                        if nm not in self.ext_by_name:
                            self.ext_by_name[nm]=sent; self.externs[sent]=nm; sent+=4
                        self._w32(off,self.ext_by_name[nm])
    def map_into(self,uc):
        PG=0x1000
        size=(len(self.img)+PG-1)&~(PG-1)
        uc.mem_map(0,size,UC_PROT_ALL)
        uc.mem_write(0,bytes(self.img))
        # extern sentinel page
        uc.mem_map(0x90000000,0x1000,UC_PROT_ALL)

