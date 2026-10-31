#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
uds_lib.py — الطبقة 4: مكتبة اتصال مستقلة (Linux-native)
========================================================
تنفيذ ذاتي الاكتفاء لـ:
  - ISO-TP (ISO 15765-2) فوق SocketCAN  -> CANTransport
  - UDS (ISO 14229) client              -> UdsClient
  - ELM327 AT-command backend           -> ElmTransport   (لأجهزة clone serial)

الهدف: القدرة على إرسال نفس الأوامر التي يرسلها برنامج الشركة
بدون أي اعتماد على Windows أو على برامجهم.

مثال:
    from uds_lib import CANTransport, UdsClient
    t = CANTransport("can0", rx_id=0x7E0, tx_id=0x7E8)
    u = UdsClient(t)
    print(u.read_dtc())
    print(u.identify())          # F190/F1A0... common VAG/ecu IDs
    u.raw(0x22, 0xF1, 0x90)      # ReadDataByIdentifier VIN
"""
import socket
import struct
import time


class TransportError(Exception):
    pass


# ------------------------------------------------------------ SocketCAN -----
class CANTransport:
    """ISO 15765-2 single+multi frame transport over Linux SocketCAN."""

    def __init__(self, iface, rx_id, tx_id, extended=False, padding=0xCC,
                 stmin_ms=0, timeout=2.0):
        self.rx_id, self.tx_id = rx_id, tx_id
        self.padding = padding
        self.stmin_ms = stmin_ms
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        if extended:
            self.rx_id |= socket.CAN_EFF_BITMASK
            self.tx_id |= socket.CAN_EFF_BITMASK
        self.sock.bind((iface,))

    def _send(self, data8):
        frame = struct.pack("<IB3x8s", self.tx_id & 0x1FFFFFFF,
                            len(data8), bytes(data8).ljust(8, bytes([self.padding])))
        self.sock.send(frame)

    def send(self, payload):
        """Send segmented ISO-TP message (SF or FF+CF)."""
        n = len(payload)
        if n <= 7:
            self._send(bytes([n]) + payload)
        else:
            ff = bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6]
            self._send(ff)
            seq = 1
            off = 6
            while off < n:
                chunk = payload[off:off + 7]
                self._send(bytes([0x20 | (seq & 0x0F)]) + chunk)
                seq = (seq + 1) & 0x0F
                off += 7
                time.sleep(self.stmin_ms / 1000 if hasattr(self, "stmin_ms") else 0)

    def recv(self):
        """Receive one complete ISO-TP message (handles SF/FF/CF/FC)."""
        buf = bytearray()
        total = None
        deadline = time.time() + self.timeout
        expect_sn = 1
        while time.time() < deadline:
            raw = self.sock.recv(16)
            can_id = struct.unpack("<I", raw[:4])[0] & 0x7FFFFFFF
            dlc = raw[4]
            data = raw[8:8 + dlc]
            if can_id != self.rx_id:
                continue
            pci = data[0]
            ftype = pci >> 4
            if ftype == 0:                      # Single Frame
                return bytes(data[1:1 + (pci & 0x0F)])
            elif ftype == 1:                    # First Frame
                total = ((pci & 0x0F) << 8) | data[1]
                buf += data[2:]
                # send Flow Control (CTS, block=0, STmin=0)
                self._send(bytes([0x30, 0x00, 0x00]))
            elif ftype == 2:                    # Consecutive Frame
                sn = pci & 0x0F
                if sn != expect_sn:
                    raise TransportError(f"ISO-TP sequence error: got {sn}, want {expect_sn}")
                expect_sn = (expect_sn + 1) & 0x0F
                buf += data[1:]
                if total and len(buf) >= total:
                    return bytes(buf[:total])
            elif ftype == 3:
                pass                             # Flow control from ECU — ignore
        raise TransportError("ISO-TP receive timeout")


# ------------------------------------------------------------------ UDS -----
NRC_NAMES = {
    0x10: "generalReject", 0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported", 0x13: "incorrectLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
    0x27: "noResponseFromSubnetComponent", 0x31: "requestOutOfRange",
    0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure", 0x78: "responsePending(ses)",
}


class NegativeResponseError(Exception):
    def __init__(self, svc, nrc):
        self.svc, self.nrc = svc, nrc
        super().__init__(f"NRC 0x{nrc:02x} ({NRC_NAMES.get(nrc, '?')}) on service 0x{svc:02x}")


class UdsClient:
    def __init__(self, transport):
        self.t = transport

    def request(self, *data, wait_pending=True):
        self.t.send(bytes(data))
        resp = self.t.recv()
        while wait_pending and len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78:
            resp = self.t.recv()          # 0x78 = responsePending
        if len(resp) >= 3 and resp[0] == 0x7F:
            raise NegativeResponseError(resp[1], resp[2])
        return resp

    # -- standard services ---------------------------------------------------
    def diagnostic_session(self, session=0x03):          # 0x01 def, 0x03 ext
        return self.request(0x10, session)

    def ecu_reset(self, mode=0x01):
        return self.request(0x11, mode)

    def clear_dtc(self):
        return self.request(0x14, 0xFF, 0xFF, 0xFF)

    def read_dtc(self, mask=0xFF):
        r = self.request(0x19, 0x02, mask)
        # r = [0x59, 0x02, availStatus] + (DTC3 + status1)*n
        dtcs = []
        for i in range(3, len(r) - 2, 4):
            code = r[i:i + 3]
            dtcs.append(f"{code[0]:02X}{code[1]:02X}{code[2]:02X}")
        return dtcs

    def security_access(self, level=0x01, seed_to_key=None):
        seed_r = self.request(0x27, level)
        seed = seed_r[2:]
        key = seed_to_key(seed) if seed_to_key else b"\x00\x00\x00\x00"
        return self.request(0x27, level + 1, *key)

    def read_data(self, did):
        return self.request(0x22, (did >> 8) & 0xFF, did & 0xFF)[3:]

    def write_data(self, did, value: bytes):
        return self.request(0x2E, (did >> 8) & 0xFF, did & 0xFF, *value)

    def tester_present(self):
        return self.request(0x3E, 0x00)

    def identify(self):
        """Pull the usual fingerprint DIDs; tolerant of failures."""
        out = {}
        for did, name in [(0xF190, "VIN"), (0xF18C, "ECU serial"),
                          (0xF17F, "software version"), (0xF180, "bootloader ID"),
                          (0x0100, "alt sw version"), (0xF197, "engine type")]:
            try:
                v = self.read_data(did)
                out[name] = v.decode("latin1", "replace").strip("\x00 ")
            except Exception as e:
                out[name] = f"<{e}>"
        return out


# ------------------------------------------------------------- ELM327 -------
class ElmTransport:
    """For serial clones speaking ELM327 AT dialect (OBD-II dongles etc.)."""

    def __init__(self, port, baud=38400, protocol="AUTO"):
        import serial
        self.s = serial.Serial(port, baud, timeout=2)
        self.cmd("ATZ")
        self.cmd("ATE0")                      # echo off
        self.cmd("ATL0")                      # linefeeds off
        self.cmd("ATSP" + ("00" if protocol == "AUTO" else protocol))

    def cmd(self, c):
        self.s.reset_input_buffer()
        self.s.write((c + "\r").encode())
        lines = []
        while True:
            ln = self.s.readline().decode(errors="replace").strip()
            if ln in ("", ">"):
                break
            lines.append(ln)
        return "\n".join(lines)

    def send(self, payload):
        self.pending_hex = payload.hex().upper()

    def recv(self):
        r = self.cmd(self.pending_hex)
        if r.startswith("BUS INIT") or "NO DATA" in r or "ERROR" in r:
            raise TransportError(f"ELM bus error: {r}")
        return bytes.fromhex(r.replace(" ", "").replace(".", ""))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="standalone UDS tester (Linux)")
    ap.add_argument("--can", help="SocketCAN iface, e.g. can0")
    ap.add_argument("--rx", type=lambda x: int(x, 0), default=0x7E0)
    ap.add_argument("--tx", type=lambda x: int(x, 0), default=0x7E8)
    ap.add_argument("--elm", help="ELM327-style serial port instead of CAN")
    ap.add_argument("--session", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--did", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dtc", action="store_true")
    args = ap.parse_args()

    if args.can:
        tr = CANTransport(args.can, args.rx, args.tx)
    elif args.elm:
        tr = ElmTransport(args.elm)
    else:
        ap.error("choose --can or --elm")
    u = UdsClient(tr)
    if args.session:
        print("[+] session:", u.diagnostic_session(args.session).hex())
    if args.did:
        print(f"[+] DID 0x{args.did:04X} =", u.read_data(args.did))
    if args.dtc:
        print("[+] DTCs:", u.read_dtc())
    if not (args.session or args.did or args.dtc):
        print("[+] identify:", u.identify())
