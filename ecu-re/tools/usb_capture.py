#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usb_capture.py — الطبقة 2+3: التقاط حركة USB وتحليلها
=====================================================
طريقتان للالتقاط حسب نوع الجهاز:

 A) أجهزة Bulk/Serial (FTDI, CH340, MCP2200 bulk, VCI cables):
    sudo tcpdump -i usbmon1 -w cap.pcap 'usb.idVendor==0x0403'
    ثم:  python3 usb_capture.py analyze cap.pcap

 B) أجهزة HID (raw-HID J2534 boxes, some TP/ECU tools):
    sudo python3 usb_capture.py hid --vid 0x1234 --pid 0x4567 --replay session.txt
    (يتطلب unbind لموديول hid إذا كانت الواجهة raw — انظر HINTS أدناه)

الأوامر:
    hid      : إرسال أوامر خام إلى جهاز HID واستقبال الردود وتسجيلها
    analyze  : تحليل pcap من usbmon وإخراج جداول أوامر/ردود مرتبة زمنياً
    hexdump  : إخراج hexdump خام لكل الحزم

مثال replay (session.txt سطر لكل رسالة، # للتعليق):
    # استعلام K-line بسيط
    81 A2 01 00 00 00 00 00
"""
import argparse
import binascii
import json
import struct
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------- HID raw ---
def hid_send_recv(vid, pid, payloads, report_id=0x00, in_len=64, timeout=2000,
                  log_path=None):
    try:
        import hid
    except ImportError:
        sys.exit("[!] pip install hidapi   ثم أعد التشغيل")
    dev = hid.Device(vid, pid)
    print(f"[+] opened HID {dev.vendor_id:#06x}:{dev.product_id:#06x} "
          f"serial={dev.serial!r}")
    transcript = []
    try:
        for idx, p in enumerate(payloads):
            data = bytes(p)
            if report_id is not None:
                data = bytes([report_id]) + data
            t0 = datetime.now(timezone.utc)
            dev.write(data)
            resp = dev.read(in_len, timeout)
            dt = (datetime.now(timezone.utc) - t0).total_seconds()
            rec = {"n": idx,
                   "tx": binascii.hexlify(bytes(p)).decode(),
                   "rx": binascii.hexlify(bytes(resp)).decode() if resp else None,
                   "rtt_ms": round(dt * 1000, 2)}
            transcript.append(rec)
            print(f"[{idx:03d}] TX {rec['tx']}")
            print(f"      RX {rec['rx']}   ({rec['rtt_ms']} ms)")
    finally:
        dev.close()
    if log_path:
        with open(log_path, "w") as f:
            json.dump(transcript, f, indent=1)
        print(f"[+] transcript -> {log_path}")
    return transcript


def parse_replay(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.lower().startswith("h:"):        # h:0A1B2C... (hex compact)
                line = line[2:]
            out.append(binascii.unhexlify(line.replace(" ", "")))
    return out


# ------------------------------------------------------------- usbmon -------
USBMON_HDR = "<iiiQQiBBBHBi"          # struct usbmon_urb_packet (compat)
SIZEOF_USBMON = struct.calcsize(USBMON_HDR)


def load_pcap_frames(path):
    """Minimal pcap reader (no scapy dependency needed on user machine)."""
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            sys.exit("[!] ليس ملف pcap صالح (ساحر=%s). استخدم tcpdump -w." %
                     binascii.hexlify(magic))
        frames = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_s, ts_us, incl, orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            frames.append(((ts_s + ts_us / 1e6), data))
        return frames


def analyze(path, show=200):
    frames = load_pcap_frames(path)
    print(f"[+] {len(frames)} frames in {path}")
    events = []
    base_t = frames[0][0] if frames else 0
    for t, data in frames:
        if len(data) < SIZEOF_USBMON:
            continue
        (tv1, tv2, type_, id_, sbc, ep, dd, bus, xfer, le, st, iso) = \
            struct.unpack(USBMON_HDR, data[:SIZEOF_USBMON])
        payload = data[SIZEOF_USBMON:SIZEOF_USBMON + le]
        ev = {"t": round(t - base_t, 6),
              "type": chr(type_), "ep": f"{ep & 0x0f:02x}",
              "dir": "OUT(host->dev)" if chr(dd) == "o" else "IN(dev->host)",
              "status": st, "len": le,
              "hex": binascii.hexlify(payload[:64]).decode()}
        events.append(ev)
    # pairing SUBMIT/COMPLETE by endpoint order = command/response pairs
    submits = [e for e in events if e["type"] == "S"]
    completes = [e for e in events if e["type"] == "C"]
    n = min(show, len(submits))
    print(f"\n{'t(s)':>9} {'EP':>3} {'DIR':>15} {'LEN':>4}  DATA")
    for e in submits[:n]:
        print(f"{e['t']:>9.4f} {e['ep']:>3} {e['dir']:>15} {e['len']:>4}  {e['hex']}")
    print(f"\n[+] submits={len(submits)} completes={len(completes)}")
    rep = path.rsplit(".", 1)[0] + "_analysis.json"
    with open(rep, "w") as f:
        json.dump(events, f, indent=1)
    print(f"[+] full event list -> {rep}")


def main():
    ap = argparse.ArgumentParser(description="USB capture & analysis for ECU tool RE")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hid", help="send raw payloads to a HID device and log replies")
    h.add_argument("--vid", type=lambda x: int(x, 0), required=True)
    h.add_argument("--pid", type=lambda x: int(x, 0), required=True)
    h.add_argument("--replay", required=True, help="file of hex commands, one per line")
    h.add_argument("--report-id", type=lambda x: int(x, 0), default=0x00)
    h.add_argument("--in-len", type=int, default=64)
    h.add_argument("--log", default="hid_transcript.json")

    a = sub.add_parser("analyze", help="parse usbmon pcap into cmd/rsp table")
    a.add_argument("pcap")
    a.add_argument("--show", type=int, default=200)

    args = ap.parse_args()
    if args.cmd == "hid":
        payloads = parse_replay(args.replay)
        hid_send_recv(args.vid, args.pid, payloads, args.report_id,
                      args.in_len, log_path=args.log)
    elif args.cmd == "analyze":
        analyze(args.pcap, args.show)


if __name__ == "__main__":
    main()
