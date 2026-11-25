#!/usr/bin/env python3
"""
pc203_keygen — rigenera le chiavi DES della camera PC203/IPC360 a partire
dall'identita' dell'account+camera, senza doverle dumpare ogni volta.

Algoritmo (ricavato reversando xmPtz::xmSetSecurity -> pw_seEncryption):

    seed = username + identifier           # identifier = deviceID (video) o MAC
    s1   = pw_seEncryption(seed, "default_ori")
    s2   = pw_seEncryption(s1,   "pro_final")
    s3   = pw_seEncryption(s2,   "extention")
    keystring = s2 + s3[:16]               # 36 caratteri = 8 chiavi DES (finestra da 8, passo 4)

Lo stream VIDEO usa la keystring derivata da (username, deviceID).

Come ottenere username / MAC / deviceID per la propria camera:
  esegui l'hook Frida `hook_keys.js` sull'app IPC360 e leggi gli argomenti di
  pw_seEncryption: in1 = <username><MAC>, in2 = <username><deviceID>.
  (lo username NON e' necessariamente la mail: per alice_x@example.com era "alice")

Richiede emu_se.py, loader.py e lib_so/libpwnativenetsdk.so nella stessa cartella.
"""
import argparse
from emu_se import se

STAGES = ("default_ori", "pro_final", "extention")


def derive_keystring(username, identifier):
    s = username + identifier
    s1 = se(s, STAGES[0])
    s2 = se(s1, STAGES[1])
    s3 = se(s2, STAGES[2])
    return s2 + s3[:16]            # 36 caratteri


def keys_from_keystring(ks):
    # 8 chiavi da 8 byte, finestra scorrevole con passo 4 sulla keystring da 36
    return [ks[4 * i:4 * i + 8] for i in range(8)]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Genera le chiavi DES della PC203/IPC360")
    ap.add_argument("username", help='es. "alice" (NON la mail intera)')
    ap.add_argument("deviceid", help='device ID della camera, es. "1234567890"')
    ap.add_argument("--mac", help='MAC della camera (opzionale), es. "001122334455"')
    a = ap.parse_args()

    ks_video = derive_keystring(a.username, a.deviceid)
    print("Keystring VIDEO (da username+deviceID):", ks_video)
    print("Chiavi DES B0..B7:", keys_from_keystring(ks_video))
    if a.mac:
        ks_mac = derive_keystring(a.username, a.mac)
        print("Keystring (da username+MAC)          :", ks_mac)
