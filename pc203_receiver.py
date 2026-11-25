#!/usr/bin/env python3
# PC203 / IPC360 local receiver  -  reverse-engineered, cloud-free
# Connette in locale alla camera, riceve lo stream, decifra i primi 1024 byte
# di ogni slice e scrive H.264 Annex-B su stdout (per ffmpeg -> RTSP -> Frigate).
#
# Uso tipico (imposta prima la TUA identita' camera e la keystring):
#   export PC203_TOKEN=... PC203_DEVICEID=... PC203_SESS2=... PC203_KEYSTRING=...
#   python3 pc203_receiver.py --host <CAMERA_IP> 2>receiver.log | \
#     ffmpeg -fflags +genpts -f h264 -i - -c copy -f rtsp rtsp://127.0.0.1:8600/pc203
#
# Dipendenze: unicorn, pyelftools, capstone  (per il DES via emulatore)
# File richiesti nella stessa cartella: loader.py, emu.py, pc203_decrypt.py,
#   lib_so/libpwnativenetsdk.so   (estratta dalla TUA app IPC360)
import socket, struct, sys, threading, time, argparse

MAGIC=b'\xcc\xdd\xee\xff'
HDR=20  # magic4 + type2 + pad2 + devtoken4 + plen4 + pad4

def log(*a): print("[recv]",*a,file=sys.stderr,flush=True)

# ---- identita' della camera --------------------------------------------------
# Sostituisci con i TUOI valori (via --token/--deviceid/--sess2, variabili
# d'ambiente PC203_TOKEN/PC203_DEVICEID/PC203_SESS2, o modificando i default qui).
# Come ricavarli: hook Frida (in1/in2 di pw_seEncryption) oppure una cattura di
# rete locale (token = header[8:12]; session1 = deviceID little-endian).
import os
def _hex4(s): return bytes.fromhex(s)[:4].ljust(4, b'\x00')
def _id_le(v): return struct.pack('<I', int(v) & 0xffffffff)   # deviceID -> session1

DEVTOKEN = _hex4(os.environ.get("PC203_TOKEN", "00000000"))      # es. a1b2c3d4
SESS1    = (_id_le(os.environ["PC203_DEVICEID"]) if os.environ.get("PC203_DEVICEID")
            else _hex4(os.environ.get("PC203_SESS1", "00000000")))  # = deviceID LE
SESS2    = _hex4(os.environ.get("PC203_SESS2", "00000000"))

def msg(mtype, payload=b''):
    total = 20 + len(payload)
    return MAGIC + struct.pack('<H', mtype) + b'\x00\x00' + DEVTOKEN + \
           struct.pack('<I', total) + b'\x00\x00\x00\x00' + payload

# ---------------- PTZ ----------------
def ptz_cmd(pan, tilt):
    # 0x4f77 relative move; int[0]=1 mode, int[3]=pan(X), int[4]=tilt(Y)
    ints=[1,0,0,int(pan),int(tilt)] + [0]*6
    payload=b''.join(struct.pack('<i',v) for v in ints)
    # coda metadati osservata (device id / session) - best effort
    payload += SESS1 + b'\x01\x00\x00\x00' + DEVTOKEN
    payload=(payload+b'\x00'*72)[:72]
    return msg(0x4f77, payload)

# ---------------- decrypt ----------------
from pc203_decrypt import _get_decoder, REL_POS, BLOCK, KEYS
_decs=[_get_decoder(k) for k in KEYS]
def decrypt_first1024(buf, origin):
    data=bytearray(buf)
    for b in range(2):
        base=origin+b*BLOCK
        for ci,rp in enumerate(REL_POS):
            pos=base+rp
            if pos+16>len(data): break
            ev=bytes(data[pos+2*k] for k in range(8))
            pl=_decs[ci](ev)
            for k in range(8): data[pos+2*k]=pl[k]
    return bytes(data)

def emit_frame(buf, out):
    # trova l'origine della slice (NAL 1 o 5) e decifra i primi 1024 byte
    pos=0; origin=None
    while True:
        sc=buf.find(b'\x00\x00\x00\x01',pos)
        if sc<0: break
        nt=buf[sc+4]&0x1f
        if nt in (1,5): origin=sc; break
        pos=sc+4
    if origin is not None:
        buf=decrypt_first1024(buf, origin)
    out.write(buf); out.flush()


# ---------------- frame parsing (split on MAGIC, validated offsets) ----------------
def iter_messages(buf):
    """frame per lunghezza totale @[12:16]; resync su MAGIC se incoerente."""
    out=[]; i=0; n=len(buf)
    while i+20<=n:
        if buf[i:i+4]!=MAGIC:
            j=buf.find(MAGIC,i+1)
            if j<0: i=n; break
            i=j; continue
        total=struct.unpack_from('<I',buf,i+12)[0]
        if total<20 or total>300000:
            j=buf.find(MAGIC,i+4)
            if j<0: break
            i=j; continue
        if i+total>n: break   # messaggio incompleto, aspetta altri dati
        m=buf[i:i+total]
        out.append((struct.unpack_from('<H',m,4)[0], m))
        i+=total
    return out, buf[i:]

def parse_video(m):
    # absolute offsets: frame#@32 frag@36 vlen@44(2B) vdata@48
    if len(m)<48: return None
    frame=struct.unpack_from('<I',m,32)[0]
    frag =struct.unpack_from('<I',m,36)[0]
    vlen =struct.unpack_from('<H',m,44)[0]
    vdata=m[48:48+vlen] if vlen else m[48:]
    return frame,frag,vdata

# ---------------- main loop ----------------
def run(host, port, out):
    # handshake costruito dall'identita' configurata (vedi in alto)
    PH_9C41 = msg(0x9c41, SESS1 + SESS2 + b'\x29\x00\x00\x00')
    PH_9C4D = msg(0x9c4d, SESS2 + b'\x29\x00\x00\x00' + b'\x01\x00\x01\x00' + SESS1)
    PH_9C42 = msg(0x9c42, SESS1 + SESS2 + b'\x29\x00\x00\x00')
    KA      = msg(0x0001)

    s=socket.create_connection((host,port), timeout=10)
    log(f"connesso a {host}:{port}")

    # --- fase 1: hello ---
    for _ in range(3): s.sendall(PH_9C41)
    s.sendall(PH_9C4D)
    log("TX fase1: 3x 0x9c41 + 0x9c4d")

    # --- attendi 0x9c4e dalla camera ---
    buf=b''; got=False; s.settimeout(6)
    try:
        while not got:
            chunk=s.recv(65536)
            if not chunk: break
            buf+=chunk
            msgs,buf=iter_messages(buf)
            for mt,m in msgs:
                log("RX", hex(mt), "len", len(m))
                if mt==0x9c4e: got=True
            if got: break
    except socket.timeout:
        log("nessun 0x9c4e entro 6s (procedo comunque)")

    # --- fase 2: rispondi con 3x 0x9c42 (IL TRIGGER) ---
    for _ in range(3): s.sendall(PH_9C42)
    log("TX fase2: 3x 0x9c42 (trigger video)")

    # --- keepalive periodici ---
    stop=threading.Event()
    def ka():
        while not stop.is_set():
            try: s.sendall(KA)
            except OSError: break
            stop.wait(2.0)
    threading.Thread(target=ka,daemon=True).start()

    # --- loop principale: video ---
    frames={}; cur=None; nvid=0
    s.settimeout(15)
    while True:
        # processa quanto gia' in buf
        msgs,buf=iter_messages(buf)
        for mtype,m in msgs:
            if mtype==0x9c45:
                pv=parse_video(m)
                if not pv: continue
                frame,frag,vdata=pv
                if cur is None: cur=frame
                if frame!=cur:
                    fr=frames.pop(cur,{})
                    data=b''.join(fr[x] for x in sorted(fr))
                    if data: emit_frame(data,out); nvid+=1
                    if nvid%50==0: log("frame emessi:",nvid)
                    cur=frame
                frames.setdefault(frame,{})[frag]=vdata
            elif mtype==0x01:
                pass
            else:
                log("RX ctrl", hex(mtype), "len", len(m))
        try: chunk=s.recv(65536)
        except socket.timeout:
            log("timeout ricezione"); break
        if not chunk: log("connessione chiusa"); break
        buf+=chunk
    stop.set(); s.close()

def selftest(path, out):
    raw=open(path,'rb').read()
    msgs,_=iter_messages(raw)
    frames={}; cur=None; n=0
    for mtype,m in msgs:
        if mtype!=0x9c45: continue
        pv=parse_video(m)
        if not pv: continue
        frame,frag,vdata=pv
        if cur is None: cur=frame
        if frame!=cur:
            fr=frames.pop(cur,{}); data=b''.join(fr[x] for x in sorted(fr))
            if data: emit_frame(data,out); n+=1
            cur=frame
        frames.setdefault(frame,{})[frag]=vdata
    log("selftest frame emessi:",n)

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--host', required=False, default=None, help='IP della camera, es. 192.168.0.50')
    ap.add_argument('--port', type=int, default=23456)
    ap.add_argument('--token', help='device token (hex 4B), es. a1b2c3d4')
    ap.add_argument('--deviceid', help='device ID decimale (deriva session1), es. 1234567890')
    ap.add_argument('--sess1', help='session1 (hex 4B) se non usi --deviceid')
    ap.add_argument('--sess2', help='session2 (hex 4B), es. aabbccdd')
    ap.add_argument('--selftest')
    a=ap.parse_args()
    if a.token: DEVTOKEN=_hex4(a.token)
    if a.deviceid: SESS1=_id_le(a.deviceid)
    elif a.sess1: SESS1=_hex4(a.sess1)
    if a.sess2: SESS2=_hex4(a.sess2)
    if a.selftest:
        selftest(a.selftest, sys.stdout.buffer)
    else:
        if not a.host:
            ap.error("serve --host <IP camera> (oppure --selftest <file>)")
        if DEVTOKEN==b'\x00'*4 or SESS1==b'\x00'*4 or SESS2==b'\x00'*4:
            log("ATTENZIONE: identita' non impostata (token/deviceid/sess2). "
                "L'handshake fallira'. Vedi README.")
        run(a.host,a.port, sys.stdout.buffer)
