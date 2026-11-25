"""
Decifratore PC203 / IPC360 - ricostruito ed emulato dalla libreria del dispositivo.
Schema (validato su frame reali):
 - ogni slice H.264 e' cifrata selettivamente a chunk da 16 byte
 - in ogni chunk solo gli 8 byte in posizione PARI formano un blocco DES
 - il DES e' CUSTOM (tabelle modificate) -> usiamo l'emulazione della .so
 - chiavi: finestra scorrevole su stringa derivata dai seed camera, reset per blocco 512
"""
from emu import new_uc, call, setkey, DEC8, THIS, SRC, DST
from unicorn.arm_const import *

# Keystring video (36 char) derivata dall'identita' della camera.
# Generala con  pc203_keygen.py <username> <deviceID>  e passala via variabile
# d'ambiente PC203_KEYSTRING (NON mettere qui la tua chiave reale se pubblichi il codice).
import os
KEYSTR_B = os.environ.get("PC203_KEYSTRING", "X" * 36)   # 36 caratteri
KEYS = [KEYSTR_B[4*i:4*i+8] for i in range(8)]   # 8 chiavi (finestra +4)

# posizioni chunk relative a un blocco da 512 byte
BLOCK = 512
REL_POS = [80, 112, 144, 208, 240, 304, 336, 400]

# costruisci 8 decoder DES emulati, uno per chiave
_decoders={}
def _get_decoder(key):
    if key not in _decoders:
        uc=new_uc(); uc.mem_write(THIS,b'\x00'*0x400); setkey(uc,key.encode())
        def d(src8, uc=uc):
            uc.mem_write(SRC,src8); uc.mem_write(DST,b'\x00'*16)
            call(uc,DEC8,r0=THIS,r1=SRC,r2=DST,r3=8)
            return bytes(uc.mem_read(DST,8))
        _decoders[key]=d
    return _decoders[key]

def decrypt_chunk(chunk16, key):
    """Decifra un chunk da 16 byte: byte pari via DES, dispari invariati."""
    ev = bytes(chunk16[i] for i in range(0,16,2))
    pl = _get_decoder(key)(ev)
    out = bytearray(chunk16)
    for k in range(8):
        out[2*k] = pl[k]
    return bytes(out)

def decrypt_slice(buf):
    """Decifra una slice (in-place logico). Funziona per multipli di 512."""
    data = bytearray(buf)
    nblocks = len(data)//BLOCK
    for b in range(nblocks):
        base = b*BLOCK
        for ci, rp in enumerate(REL_POS):
            pos = base+rp
            key = KEYS[ci % 8]
            data[pos:pos+16] = decrypt_chunk(bytes(data[pos:pos+16]), key)
    return bytes(data)

if __name__=="__main__":
    ok_all=True
    for fi in range(4):
        enc=open(f'frames/fr{fi}_enc.bin','rb').read()
        dec=open(f'frames/fr{fi}_dec.bin','rb').read()
        my=decrypt_slice(enc)
        match = my==dec
        ok_all &= match
        ndiff=sum(1 for a,b in zip(my,dec) if a!=b)
        print(f"frame {fi}: {'OK - identico al decifrato del dispositivo' if match else f'DIFF {ndiff} byte'}")
    print("\n>>> TUTTI I FRAME RIPRODOTTI <<<" if ok_all else "\n>>> ci sono differenze <<<")
