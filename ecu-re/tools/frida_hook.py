#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frida_hook.py — طبقة 3 (Protocol RE): اعتراض اتصالات برامج الشركات المباشرة.

بدل التقاط USB pcap (الذي يخفي التشفير داخل الجهاز)، هذا الأداة تعترض النداءات
داخل عملية برنامج Windows/Linux نفسه:
  * net/ssl  : أي اتصال TCP localhost أو TLS للخادم المحلي/الدونغل
  * serial   : WriteFile/ReadFile, write()/read() على مقابلات COM/ttyS
  * hid      : HidD_SetOutputReport / write على /dev/hidraw*
  * crypto   : CryptEncrypt/Decrypt, EVP_*, RSA_* — لكشف مفاتيح seed/key قبل الاستخدام

الاستخدام:
  # Windows (بعد pip install frida-tools، وشغّل كـ Administrator):
  python frida_hook.py --spawn "C:\\Path\\tool.exe" --mode serial,hid,crypto
  python frida_hook.py --attach "ToolName.exe" --mode all

  # Linux (WSL2 لا يصل GUI apps؛ استخدم VM ويندوز أو native linux tool):
  sudo python3 frida_hook.py --attach diag-tool --mode serial,crypto

الناتج: transcript JSON-lines في reports/data/frida_<pid>_<ts>.log قابل للتحليل بـ:
  python tools/proto_find.py pattern <transcript>
"""
import argparse, json, sys, time, os

# NOTE: JS is authored as a plain template with __TOKEN__ placeholders (no f-string
# brace escaping — that was the source of a SyntaxError when `out:` appeared as an
# object key right after a doubled brace). Substitution happens in build_js().
JS_TEMPLATE = r"""
'use strict';
var MODES = __MODES__;
var MAXLEN = __MAXLEN__;

var out = function(o) { send(o); };
var hex = function(buf, n) {
    if (!buf || buf.isNull()) return null;
    var len = Math.min(n || 64, MAXLEN);
    if (len <= 0 || len > MAXLEN * 4) len = 64;
    var b = new Uint8Array(buf.readByteArray(len));
    var s = '';
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
};

function hookIf(modname, fname, callbacks) {
    // Frida 17 removed the (modname|null, fname) form of Module.findExportByName.
    // Resolve explicitly: named module -> global export -> scan loaded modules.
    var p = null;
    if (modname) {
        try {
            var m = Process.findModuleByName(modname);
            if (m) p = m.findExportByName(fname);
        } catch (e) {}
    }
    if (!p) { try { p = Module.findGlobalExportByName(fname); } catch (e) {} }
    if (!p && !modname) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            try { p = mods[i].findExportByName(fname); if (p) break; } catch (e) {}
        }
    }
    if (p) { try { Interceptor.attach(p, callbacks); out({ ev: 'hooked', fn: fname }); } catch (e) {} }
}

// ---------- SERIAL / generic file I/O ----------
if (MODES.indexOf('serial') >= 0) {
    // Windows: WriteFile/ReadFile on COM handles
    hookIf('kernel32.dll', 'WriteFile', {
        onEnter: function (a) { this.h = a[0]; this.buf = a[1]; this.n = a[2]; },
        onLeave: function (r) {
            var want = 64;
            try { want = this.n.toInt32(); } catch (e) {}
            out({ ev: 'WriteFile', h: this.h.toInt32(), data: hex(this.buf, want) });
        }
    });
    hookIf('kernel32.dll', 'ReadFile', {
        onEnter: function (a) { this.buf = a[1]; this.n = a[2]; },
        onLeave: function (r) {
            if (r.toInt32() === 0) return;
            var want = 64;
            try { want = this.n.toInt32(); } catch (e) {}
            out({ ev: 'ReadFile', data: hex(this.buf, want) });
        }
    });
    // POSIX: write/read on ttyS*/hidraw fds (log all; filter offline)
    hookIf(null, 'write', {
        onEnter: function (a) {
            var fd = a[0].toInt32();
            if (fd > 2) out({ ev: 'posix_write', fd: fd, data: hex(a[1], a[2].toInt32()) });
        }
    });
    hookIf(null, 'read', {
        onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
        onLeave: function (r) {
            var n = r.toInt32();
            if (this.fd > 2 && n > 0) out({ ev: 'posix_read', fd: this.fd, data: hex(this.buf, n) });
        }
    });
}

// ---------- HID ----------
if (MODES.indexOf('hid') >= 0) {
    hookIf('hid.dll', 'HidD_SetOutputReport', {
        onEnter: function (a) {
            var n = 65;
            try { n = a[3].toInt32() + 1; } catch (e) {}
            out({ ev: 'HID_OUT', data: hex(a[2], n) });
        }
    });
    hookIf('hid.dll', 'HidD_GetInputReport', {
        onEnter: function (a) { this.buf = a[1]; },
        onLeave: function (r) { if (r.toInt32()) out({ ev: 'HID_IN', data: hex(this.buf) }); }
    });
    hookIf(null, 'hid_write', {
        onEnter: function (a) { out({ ev: 'libusb_hid_out', data: hex(a[1], a[2].toInt32()) }); }
    });
}

// ---------- NET (localhost dongle servers / TCP to vehicle interfaces) ----------
if (MODES.indexOf('net') >= 0) {
    hookIf(null, 'send', {
        onEnter: function (a) { out({ ev: 'send', n: a[2].toInt32(), data: hex(a[1], a[2].toInt32()) }); }
    });
    hookIf(null, 'recv', {
        onEnter: function (a) { this.buf = a[1]; this.n = a[2].toInt32(); },
        onLeave: function (r) { var k = r.toInt32(); if (k > 0) out({ ev: 'recv', n: k, data: hex(this.buf, k) }); }
    });
    hookIf('ws2_32.dll', 'WSASend', {
        onEnter: function (a) {
            try {
                var lp = a[1];
                var len = lp.add(Process.pointerSize).readUInt32();
                var buf = lp.readPointer();
                out({ ev: 'wsasend', n: len, data: hex(buf, len) });
            } catch (e) {}
        }
    });
    hookIf('ws2_32.dll', 'WSARecv', {
        onEnter: function (a) { this.lp = a[1]; },
        onLeave: function (r) {
            if (r.toInt32() !== 0) return;
            try {
                var len = this.lp.add(Process.pointerSize).readUInt32();
                out({ ev: 'wsarecv', n: len, data: hex(this.lp.readPointer(), len) });
            } catch (e) {}
        }
    });
    // TLS layer (in case it talks to cloud despite being "offline")
    hookIf(null, 'SSL_write', {
        onEnter: function (a) { out({ ev: 'TLS_out', data: hex(a[2], a[3].toInt32()) }); }
    });
    hookIf(null, 'SSL_read', {
        onEnter: function (a) { this.b = a[2]; },
        onLeave: function (r) { var k = r.toInt32(); if (k > 0) out({ ev: 'TLS_in', data: hex(this.b, k) }); }
    });
}

// ---------- CRYPTO (catch keys/seeds in the clear before use) ----------
if (MODES.indexOf('crypto') >= 0) {
    hookIf('advapi32.dll', 'CryptEncrypt', {
        onEnter: function (a) {
            this.inbuf = a[3]; this.inout = a[4]; this.lenptr = a[5];
            try { this.len = a[5].readUInt32(); this.captured = hex(a[3], Math.min(this.len, 512)); }
            catch (e) { this.captured = null; }
        },
        onLeave: function () {
            try {
                var encLen = this.lenptr.readUInt32();
                var src = this.inout.isNull() ? this.inbuf : this.inout.readPointer();
                out({ ev: 'CryptEncrypt', input: this.captured, cipher: hex(src, encLen) });
            } catch (e) {}
        }
    });
    hookIf('advapi32.dll', 'CryptDecrypt', {
        onEnter: function (a) {
            try { this.len = a[5].readUInt32(); this.captured = hex(a[3], Math.min(this.len, 512)); }
            catch (e) { this.captured = null; }
        },
        onLeave: function () { out({ ev: 'CryptDecrypt', ciphertext: this.captured }); }
    });
    hookIf(null, 'EVP_Cipher', {
        onEnter: function (a) { out({ ev: 'EVP_Cipher_ctx', ctx: a[0].toString() }); }
    });
    hookIf(null, 'RSA_public_encrypt', {
        onEnter: function (a) { out({ ev: 'RSA_enc', len: a[0].toInt32(), data: hex(a[1], a[0].toInt32()) }); }
    });
    hookIf(null, 'RSA_private_decrypt', {
        onEnter: function (a) { this.l = a[0].toInt32(); this.from = a[1]; this.to = a[3]; },
        onLeave: function (r) { out({ ev: 'RSA_dec', data: hex(this.from, this.l), plain: hex(this.to, r.toInt32()) }); }
    });
}

out({ ev: 'ready', modes: MODES });
"""


def build_js(modes, maxlen):
    return (JS_TEMPLATE
            .replace("__MODES__", json.dumps(modes))
            .replace("__MAXLEN__", str(int(maxlen))))


def main():
    ap = argparse.ArgumentParser(description="Frida protocol interceptor for OEM ECU tools")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--attach", help="process name or PID")
    g.add_argument("--spawn", help="path to exe to spawn (Windows tools usually need this)")
    ap.add_argument("--mode", default="serial,hid,net,crypto",
                    help="comma list: serial,hid,net,crypto,all")
    ap.add_argument("--maxlen", type=int, default=512, help="max bytes captured per call")
    ap.add_argument("--out", default=None, help="transcript path (default reports/data/frida_TS.log)")
    args = ap.parse_args()

    modes = ["serial","hid","net","crypto"] if args.mode=="all" else [m.strip() for m in args.mode.split(",")]
    ts = time.strftime("%Y%m%d_%H%M%S")
    outp = args.out or os.path.join("reports", "data", f"frida_{ts}.log")
    os.makedirs(os.path.dirname(outp), exist_ok=True)

    import frida
    js = build_js(modes, args.maxlen)

    count = [0]
    fh = open(outp, "a", encoding="utf-8")
    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg["payload"]
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n"); fh.flush()
            count[0] += 1
            ev = payload.get("ev")
            if ev != "hooked":
                d = payload.get("data") or payload.get("in") or ""
                print(f"[{ev:>14}] {str(d)[:96]}")
        elif msg.get("type") == "error":
            print("JS error:", msg.get("description"), file=sys.stderr)

    target = int(args.attach) if args.attach and args.attach.isdigit() else args.attach
    if args.spawn:
        pid = frida.spawn(args.spawn)
        session = frida.attach(pid)
        print(f"[*] spawned pid={pid}; start the device handshake now, Ctrl-C to stop")
    else:
        session = frida.attach(target)
        print(f"[*] attached to {target}; perform operations in the tool, Ctrl-C to stop")

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        try: session.detach()
        except Exception: pass
        fh.close()
        print(f"\n[*] {count[0]} events -> {outp}")
        print(f"[*] next: python tools/proto_find.py pattern {outp}")


if __name__ == "__main__":
    main()
