#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proto_find.py — الطبقة 3: اكتشاف بروتوكولات الاتصال
===================================================
بعد أن نعرف شكل الحوامل (carrier) التي يستخدمها الجهاز، نحتاج اكتشاف
"لغة" الرسائل. هذا السكربت يوفر:

1) محلل UDS/ISO 14229 على مستوى النقل لعدة حوامل في آنٍ واحد:
   - ISO-TP over CAN (can0 / vcan0)            [SocketCAN]
   - KWP2000 / ISO 9141-2 on K-line serial      [/dev/ttyUSBx]
   - ELM327 AT-command layer                    [/dev/ttyACMx, bluetooth rfcomm]

2) "منبّه البروتوكول المجهول": يسجل كل حركة ويبحث عن أنماط:
   - رأس ثابت أول بايت/بايتين في >N% من رسائل OUT  => header محتمل
   - أطوال قياسية (64-byte HID reports, 5-byte framing...)
   - أوامر متكررة بنفس البادئة مع اختلاف ذيل => opcode table محتملة

الاستخدام:
    python3 proto_find.py can --iface can0              # مراقبة سلبية + بث استعلامات ID القياسية
    python3 proto_find.py kwp --port /dev/ttyUSB0        # K-line 9600 8E1
    python3 proto_find.py elm --port /dev/ttyACM0        # ELM327 clone discovery
    python3 proto_find.py pattern hid_transcript.json    # تحليل نمط من transcript سابق
"""
import argparse
import binascii
import json
import sys
from collections import Counter

# --------------------------------------------------------------- UDS -------
UDS_SERVICE_NAMES = {
    0x01: "DiagnosticSessionControl", 0x02: "ECUReset", 0x03: "ClearDTCs",
    0x04: "TestPresent", 0x05: "SecurityAccess", 0x06: "CommunicationControl",
    0x07: "ProtocolControl", 0x08: "ResponseOnEvent", 0x09: "ReadDataByIdentifier",
    0x0A: "ReadMemoryByAddress", 0x0B: "WriteDataByIdentifier",
    0x0C: "WriteMemoryByAddress", 0x0D: "ReadScalableDataByIdentifier",
    0x0E: "WriteScalableDataByIdentifier", 0x0F: "InputOutputControlByIdentifier",
    0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier", 0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier", 0x27: "SecurityAccess", 0x28: "CommunicationControl",
    0x29: "Authentication", 0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier", 0x2F: "InputOutputControlByIdentifier",
    0x30: "InputOutputControlByLocalIdentifier", 0x31: "RoutineControl",
    0x34: "RequestDownload", 0x35: "RequestUpload", 0x36: "TransferData",
    0x37: "RequestTransferExit", 0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress", 0x3E: "TesterPresent",
    0x83: "AccessTimingParameter", 0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting", 0x86: "ResponseOnEvent", 0x87: "LinkControl",
}


def decode_uds(data):
    """Best-effort single-frame ISO-TP/UDS decode."""
    b = bytes(data)
    if not b:
        return None
    out = {"raw": binascii.hexlify(b).decode()}
    # strip ISO-TP PCI (assume single frame, len<=7 in CAN) or serial framing
    svc = b[0]
    pos = 1
    if svc in (0x10, 0x11, 0x27, 0x31, 0x3E) or (0x01 <= svc <= 0x3F and svc not in (0x00,)):
        pass
    name = UDS_SERVICE_NAMES.get(svc & 0x7F)
    neg = (svc & 0xF0) == 0x50 or svc == 0x7F
    if svc == 0x7F and len(b) >= 3:
        out["type"] = "negative response"
        out["service"] = f"0x{b[1]:02x} {UDS_SERVICE_NAMES.get(b[1], '?')}"
        out["nrc"] = f"0x{b[2]:02x}"
        return out
    if name:
        out["type"] = "response" if (svc & 0x40) else "request"
        out["service"] = f"0x{svc:02x} {name}"
        out["payload"] = binascii.hexlify(b[pos:]).decode()
    return out


# ------------------------------------------------------------- SocketCAN ----
def monitor_can(iface, sniff_seconds=10, ids=None):
    try:
        from scapy.all import sniff, send, CAN, AsyncSender
    except ImportError:
        sys.exit("[!] pip install scapy ; requires Linux SocketCAN (modprobe vcan / can)")
    print(f"[*] listening on {iface} for {sniff_seconds}s ...")
    pkts = sniff(iface=iface, timeout=sniff_seconds,
                 filter="can" if False else None, prn=lambda p: None)
    seen = Counter()
    for p in pkts:
        if hasattr(p, "identifier"):
            seen[(p.identifier, bytes(p.Data)[:2])] += 1
            d = decode_uds(bytes(p.Data))
            if d:
                print(f"CAN id=0x{p.identifier:03x} len={len(p.Data)} -> {d}")
    print("\n[top talkers id+first2bytes]")
    for k, c in seen.most_common(15):
        print(f"  id=0x{k[0]:03x} head={binascii.hexlify(k[1]).decode():>4} x{c}")


# ---------------------------------------------------------------- K-line ----
def monitor_kwp(port, baud=9600, seconds=10):
    import serial, time
    s = serial.Serial(port, baud, parity=serial.PARITY_EVEN,
                      bytesize=8, stopbits=1, timeout=0.2)
    end = time.time() + seconds
    buf = bytearray()
    print(f"[*] K-line listen {port}@{baud} 8E1 for {seconds}s (Ctrl-C to stop)")
    while time.time() < end:
        chunk = s.read(256)
        if chunk:
            buf += chunk
            sys.stdout.write("."); sys.stdout.flush()
    s.close()
    print(f"\n[+] captured {len(buf)} bytes")
    print(binascii.hexlify(bytes(buf[:512])).decode())
    with open("kline_capture.bin", "wb") as f:
        f.write(bytes(buf))


# ---------------------------------------------------------------- ELM327 ----
def probe_elm(port, seconds=5):
    import serial, time
    s = serial.Serial(port, 38400, timeout=0.5)
    tests = ["ATZ", "ATI", "ATL1", "ATV1", "ATSP0", "ATDP", "ATRV", "0100", "0900"]
    for t in tests:
        s.reset_input_buffer()
        s.write((t + "\r").encode())
        time.sleep(seconds / 4)
        resp = s.read(s.in_waiting or 1)
        print(f"TX {t!r:10} RX {resp!r}")
    s.close()


# ------------------------------------------------------------ pattern -------
def _load_records(transcript_path):
    """Accept three formats: JSON array, JSON-lines (frida_hook output), or a
    plain hex-dump text file. Returns list of {tx, rx} dicts."""
    raw = open(transcript_path, encoding="utf-8", errors="replace").read().strip()
    if not raw:
        return []
    # 1) single JSON document (array of objects)
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            obj = [obj]
        return [r for r in obj if isinstance(r, dict)]
    except json.JSONDecodeError:
        pass
    # 2) JSON lines — frida_hook transcript: pair out→in events by direction
    recs, pending_out = [], None
    is_jsonl = False
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        is_jsonl = True
        e = ev.get("ev", "")
        data = ev.get("data") or ev.get("input") or ""
        if e in ("posix_write", "WriteFile", "HID_OUT", "libusb_hid_out",
                 "send", "wsasend", "TLS_out"):
            if pending_out is not None:
                recs.append({"tx": pending_out, "rx": ""})
            pending_out = data
        elif e in ("posix_read", "ReadFile", "HID_IN", "recv", "wsarecv", "TLS_in"):
            if pending_out is not None:
                recs.append({"tx": pending_out, "rx": data}); pending_out = None
            else:
                recs.append({"tx": "", "rx": data})
    if pending_out is not None:
        recs.append({"tx": pending_out, "rx": ""})
    if is_jsonl:
        return recs
    # 3) fallback: treat each whitespace-separated hex token as a TX blob
    toks = [t for t in raw.replace(",", " ").split() if all(c in "0123456789abcdefABCDEF" and len(t) >= 2 for c in t)]
    return [{"tx": t, "rx": ""} for t in toks]


def find_patterns(transcript_path):
    """Analyze a list of TX/RX hex records for structural patterns."""
    recs = _load_records(transcript_path)
    if not recs:
        print("[!] لم يُعثر على أي سجلات قابلة للتحليل في الملف."); return
    tx_heads = Counter()
    tx_lens = Counter()
    rx_lens = Counter()
    for r in recs:
        tx = binascii.unhexlify(r["tx"]) if isinstance(r.get("tx"), str) and r.get("tx") else b""
        rx = binascii.unhexlify(r["rx"]) if isinstance(r.get("rx"), str) and r.get("rx") else b""
        if len(tx) >= 2:
            tx_heads[tx[:2]] += 1
        tx_lens[len(tx)] += 1
        rx_lens[len(rx)] += 1
    print(json.dumps({
        "messages": len(recs),
        "tx_len_hist": dict(sorted(tx_lens.items())),
        "rx_len_hist": dict(sorted(rx_lens.items())),
        "top_tx_headers": {binascii.hexlify(k).decode(): v
                           for k, v in tx_heads.most_common(12)},
    }, indent=1, ensure_ascii=False))
    print("\n[?] فرضيات: إذا كانت الأطوال ثابتة (مثلاً 64) فالناقل HID reports؛ "
          "الرؤوس المتكررة هي opcodes الجهاز وليست UDS مباشرة — "
          "جرّب فك التغليف: غالباً byte0=direction/cmd-class, byte1=subcmd.")


def main():
    ap = argparse.ArgumentParser(description="protocol discovery helper")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("can");  c.add_argument("--iface", default="can0")
    c.add_argument("--secs", type=int, default=10)
    k = sub.add_parser("kwp");  k.add_argument("--port", required=True)
    k.add_argument("--baud", type=int, default=9600); k.add_argument("--secs", type=int, default=10)
    e = sub.add_parser("elm");  e.add_argument("--port", required=True)
    p = sub.add_parser("pattern"); p.add_argument("transcript")
    args = ap.parse_args()
    if args.cmd == "can":
        monitor_can(args.iface, args.secs)
    elif args.cmd == "kwp":
        monitor_kwp(args.port, args.baud, args.secs)
    elif args.cmd == "elm":
        probe_elm(args.port)
    elif args.cmd == "pattern":
        find_patterns(args.transcript)


if __name__ == "__main__":
    main()
