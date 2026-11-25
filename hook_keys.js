'use strict';
// Hook su pw_seEncryption per vedere come si monta la keystring video.
// pw_seEncryption(char* in1, char* in2, char* out, int len)
//   in1 = user+MAC, in2 = user+ID (osservati), out = buffer risultato, len >= 21
var LIB = 'libpwnativenetsdk.so';
var MANGLED = '_Z15pw_seEncryptionPcS_S_i';
var OFFSET = 0x1c5e50;   // indirizzo nella .so (thumb)

function resolve() {
  try { var a = Module.findExportByName(LIB, MANGLED); if (a) return a; } catch (e) {}
  try {
    var m = Process.getModuleByName(LIB);
    try { var a2 = m.getExportByName(MANGLED); if (a2) return a2; } catch (e) {}
    return m.base.add(OFFSET);
  } catch (e) {}
  return null;
}

var n = 0;
function install() {
  var addr = resolve();
  if (!addr) return false;
  console.log('[+] pw_seEncryption @ ' + addr);
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try { this.in1 = args[0].readUtf8String(); } catch (e) { this.in1 = '<?>'; }
      try { this.in2 = args[1].readUtf8String(); } catch (e) { this.in2 = '<?>'; }
      this.out = args[2];
      try { this.len = args[3].toInt32(); } catch (e) { this.len = -1; }
    },
    onLeave: function (ret) {
      var o = '<?>';
      try { o = this.out.readUtf8String(); } catch (e) {}
      n++;
      console.log('KEYCALL #' + n +
                  ' in1=' + JSON.stringify(this.in1) +
                  ' in2=' + JSON.stringify(this.in2) +
                  ' len=' + this.len +
                  ' OUT=' + JSON.stringify(o));
    }
  });
  return true;
}

if (!install()) {
  console.log('[.] libreria non ancora caricata, attendo...');
  var iv = setInterval(function () { if (install()) clearInterval(iv); }, 300);
}
