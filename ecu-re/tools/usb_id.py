#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usb_id.py — الطبقة 1+2: Hardware & USB Identification
======================================================
يقرأ descriptors الحقيقية للجهاز (VID/PID, iManufacturer/iProduct strings,
class/subclass/protocol, configurations, interfaces, endpoints) مباشرة من
USB — بعيداً عن الأسماء المضللة في Windows/Linux.

كذلك يمسح /sys/bus/usb للأنظمة التي لا يتوفر فيها pyusb بشكل كامل،
ويستخرج "بصمة" قابلة للمقارنة عبر الأجهزة (chip fingerprint).

الاستخدام:
    sudo python3 usb_id.py                 # كل الأجهزة المتصلة
    sudo python3 usb_id.py --vid 0x1234    # فلتر حسب VID
    sudo python3 usb_id.py --json out.json # حفظ التقرير JSON
    python3 usb_id.py --sysfs-only         # بدون pyusb، عبر /sys فقط

ملاحظة: يجب تشغيل الجهاز على جهاز المستخدم (هذه البيئة السحابية لا تحتوي
على منافذ USB). الناتج يُرفع لاحقاً إلى مستودع التحليل.
"""
import argparse
import json
import sys
import os
from datetime import datetime, timezone

# أشهر شرائح USB المستخدمة في أدوات ECU/TCU الصينية/المقلَّدة.
# VID وحده يكفي غالباً لكشف الشريحة الحقيقية داخل الجهاز حتى لو
# كان اسم المنتج في Windows يقول شيئاً آخر.
KNOWN_CHIPS = {
    (0x04D8, None): "Microchip MCP2200 / PICKit-derived (FTDI-like serial or raw HID)",
    (0x0403, None): "FTDI FT232R/FT232H/FT2232 (very common in clone KKL/VAG-COM cables)",
    (0x1A86, None): "WCH CH340/CH341/CH375 (common in cheap Chinese interfaces)",
    (0x10C4, None): "Silicon Labs CP210x UART bridge",
    (0x16C0, None): "Van Daal Industries / DIY AVR devices (some VAG clones)",
    (0x067B, None): "Prolific PL2303 (older clone cables; often faked PIDs)",
    (0x16D0, None): "Ali Corp / some J2534 passthrough re-branders",
    (0x0FCF, None): "MCUdude Canable / Cicada (CAN-HS family)",
    (0x2001, None): "some TWAI/CAN adapters",
    (0x1234, None): "QEMU/virtual or badly-faked VID (suspicious!)",
    (0x0EA0, None): "OBDLink / OneBridge CAN adapters",
    (0x0403, 0x6001): "FTDI FT232R as generic serial — typical of fake 'ELM327 Bluetooth' USB dongles",
    (0x16D0, 0x0D39): "J2534 PassThru style device id seen on Tactrix Openport clones",
    (0x16D0, 0x1094): "Tactrix/Openport 2.0 genuine-style id",
}


def chip_guess(vid, pid):
    exact = KNOWN_CHIPS.get((vid, pid))
    if exact:
        return exact
    base = KNOWN_CHIPS.get((vid, None))
    if base:
        return base + f" [assembled with PID 0x{pid:04x}]"
    return "UNKNOWN — needs descriptor string analysis"


def scan_sysfs():
    """Fallback: pull the same info from /sys/bus/usb/devices without libusb."""
    devs = []
    root = "/sys/bus/usb/devices"
    if not os.path.isdir(root):
        return devs
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d)
        try:
            with open(os.path.join(p, "idVendor")) as f:
                vid = int(f.read().strip(), 16)
            with open(os.path.join(p, "idProduct")) as f:
                pid = int(f.read().strip(), 16)
        except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError):
            continue

        def read(name):
            try:
                with open(os.path.join(p, name)) as f:
                    return f.read().strip()
            except OSError:
                return None

        devs.append({
            "path": d,
            "vid": vid, "pid": pid,
            "bDeviceClass": read("bDeviceClass"),
            "manufacturer": read("manufacturer"),
            "product": read("product"),
            "serial": read("serial"),
            "bNumConfigurations": read("bNumConfigurations"),
            "maxchild": read("bMaxChildInterfaces") or read("maxchild"),
            "speed": read("speed"),
            "authorized": read("authorized"),
            "driver": os.path.basename(os.path.realpath(os.path.join(p, "driver")))
                      if os.path.exists(os.path.join(p, "driver")) else None,
        })
    return devs


def dump_pyusb(vid_filter=None):
    import usb.core
    import usb.util
    out = []
    for dev in usb.core.find(find_all=True):
        vid, pid = dev.idVendor, dev.idProduct
        if vid_filter and vid != vid_filter:
            continue
        info = {
            "vid": vid, "pid": pid,
            "bcdUSB": hex(dev.bcdUSB),
            "bDeviceClass": dev.bDeviceClass,
            "bDeviceSubClass": dev.bDeviceSubClass,
            "bDeviceProtocol": dev.bDeviceProtocol,
            "max_packet_size0": dev.bMaxPacketSize0,
            "iManufacturer": None, "iProduct": None, "iSerialNumber": None,
            "configurations": [],
        }
        try:
            dev.open()
            for idx, name in ((dev.iManufacturer, "iManufacturer"),
                              (dev.iProduct, "iProduct"),
                              (dev.iSerialNumber, "iSerialNumber")):
                if idx:
                    try:
                        info[name] = usb.util.get_string(dev, idx)
                    except Exception as e:
                        info[name] = f"<error: {e}>"
            for cfg in dev:
                c = {"bConfigurationValue": cfg.bConfigurationValue,
                     "bmAttributes": cfg.bmAttributes,
                     "interfaces": []}
                for intf in cfg:
                    i = {"bInterfaceNumber": intf.bInterfaceNumber,
                         "bAlternateSetting": intf.bAlternateSetting,
                         "bInterfaceClass": intf.bInterfaceClass,
                         "bInterfaceSubClass": intf.bInterfaceSubClass,
                         "bInterfaceProtocol": intf.bInterfaceProtocol,
                         "endpoints": []}
                    for ep in intf:
                        i["endpoints"].append({
                            "bEndpointAddress": hex(ep.bEndpointAddress),
                            "bmAttributes": ep.bmAttributes,
                            "wMaxPacketSize": ep.wMaxPacketSize,
                            "bInterval": ep.bInterval,
                            "direction": "IN" if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT",
                            "type": usb.util.endpoint_type(ep.bmAttributes),
                        })
                    c["interfaces"].append(i)
                info["configurations"].append(c)
            dev.close()
        except Exception as e:
            info["error"] = str(e)
            info["hint"] = ("لا يمكن فتح الجهاز — جرّب sudo، أو أزل موديول kmod "
                            "المحتكر للواجهة (cdc_acm/ftdi_sio/ch341/usbtiny...) "
                            "أو استخدم detach_kernel_driver في pyusb.")
        out.append(info)
    return out


def main():
    ap = argparse.ArgumentParser(description="USB hardware reverse-engineering scanner for ECU tools")
    ap.add_argument("--vid", type=lambda x: int(x, 0), default=None, help="filter by VID, e.g. 0x0403")
    ap.add_argument("--json", dest="json_out", help="write report to JSON file")
    ap.add_argument("--sysfs-only", action="store_true", help="do not use pyusb/libusb")
    args = ap.parse_args()

    report = {"generated_utc": datetime.now(timezone.utc).isoformat(),
              "platform": sys.platform, "devices": []}

    if not args.sysfs_only:
        try:
            report["devices"] = dump_pyusb(args.vid)
            report["source"] = "pyusb/libusb (full descriptors)"
        except ImportError:
            report["source"] = "pyusb unavailable -> sysfs fallback"

    if not report["devices"]:
        sysd = scan_sysfs()
        if args.vid:
            sysd = [d for d in sysd if d["vid"] == args.vid]
        for d in sysd:
            d["chip_guess"] = chip_guess(d["vid"], d["pid"])
        report["devices"].extend(sysd)
        report.setdefault("source", "sysfs (limited descriptors)")

    for d in report["devices"]:
        if "chip_guess" not in d and "vid" in d and "pid" in d:
            d["chip_guess"] = chip_guess(d["vid"], d["pid"])

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[+] saved -> {args.json_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
