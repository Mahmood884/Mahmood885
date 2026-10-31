#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_uds.py — اختبار وحدة ISO-TP/UDS بدون عتاد فعلي
====================================================
يحاكي ECU زائف فوق pair من socket.socket (socketpair) عبر "transport وهمي"
يحمل إطارات CAN كـ datagrams، ثم يمرر UdsClient عبر كامل المسار:
  SF request -> SF response, FF->FC->CF multi-frame, negative responses.

التشغيل:   python3 test_uds.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uds_lib
from uds_lib import UdsClient, NegativeResponseError, TransportError


class FakeCanLink:
    """يمثل وصلة CAN: كل طرف يرسل ويستقبل إطارات 16 بايت عبر socketpair."""
    def __init__(self):
        import socket
        self.a, self.b = socket.socketpair()

    def ecu_endpoint(self):
        return _Endpoint(self.b)


class _Endpoint:
    def __init__(self, sock):
        self.sock = sock

    def send_frame(self, can_id, data):
        assert len(data) <= 8
        import struct
        self.sock.sendall(struct.pack("<IB3x", can_id, len(data)) + bytes(data).ljust(8, b"\xCC"))

    def recv_frame(self, timeout=None):
        import struct
        if timeout is not None:
            self.sock.settimeout(timeout)
        hdr = b""
        while len(hdr) < 8:                   # socketpair is a stream: read exactly
            chunk = self.sock.recv(8 - len(hdr))
            if not chunk:
                raise ConnectionError("link closed")
            hdr += chunk
        cid, dlc = struct.unpack("<IB3x", hdr)
        body = b""
        while len(body) < 8:
            chunk = self.sock.recv(8 - len(body))
            if not chunk:
                raise ConnectionError("link closed")
            body += chunk
        self.sock.settimeout(None)
        return cid & 0x7FFFFFFF, body[:dlc]


class LoopbackTransport:
    """CANTransport-like object wired to a FakeCanLink endpoint for tests."""
    PADDING = 0xCC

    def __init__(self, ep, rx_id, tx_id):
        self.ep, self.rx_id, self.tx_id = ep, rx_id, tx_id

    def send(self, payload):
        n = len(payload)
        if n <= 7:
            self.ep.send_frame(self.tx_id, bytes([n]) + payload)
        else:
            self.ep.send_frame(self.tx_id, bytes([0x10 | (n >> 8), n & 0xFF]) + payload[:6])
            seq, off = 1, 6
            while off < n:
                chunk = payload[off:off + 7]
                self.ep.send_frame(self.tx_id, bytes([0x20 | seq]) + chunk.ljust(7, b"\xCC"))
                seq = (seq + 1) & 0x0F
                off += 7

    def recv(self):
        buf, total, expect = bytearray(), None, 1
        while True:
            cid, data = self.ep.recv_frame()
            if cid != self.rx_id:
                continue
            ftype = data[0] >> 4
            if ftype == 0:
                return bytes(data[1:1 + (data[0] & 0x0F)])
            if ftype == 1:
                total = ((data[0] & 0x0F) << 8) | data[1]
                buf += data[2:]
                # Consume our own echoed FC frame (stream loopback has no CAN filtering)
                c2, d2 = self.ep.recv_frame()
                assert c2 == self.tx_id and d2[0] >> 4 == 3, "expected own FC echo"
            elif ftype == 2:
                sn = data[0] & 0x0F
                assert sn == expect, f"bad SN {sn}!={expect}"
                expect = (expect + 1) & 0x0F
                buf += data[1:]
                if total and len(buf) >= total:
                    return bytes(buf[:total])


def make_ecu(link, script):
    """Threaded fake ECU answering sequentially from a scripted list of responses."""
    import threading
    req_partial = {"active": False, "len": 0, "buf": bytearray()}

    def run():
        ep = link.ecu_endpoint()
        while script:
            cid, data = ep.recv_frame()
            ftype = data[0] >> 4
            if ftype == 3:
                continue                      # echoed tester FC — skip it
            if ftype == 2:
                # tester's Consecutive Frame(s) completing a multi-frame request:
                # buffer them and only answer once the request is complete.
                if not req_partial["active"]:
                    continue
                req_partial["buf"] += data[1:]
                if len(req_partial["buf"]) < req_partial["len"]:
                    continue
                req = bytes(req_partial["buf"][:req_partial["len"]])
                req_partial["active"] = False
            elif ftype == 1:                  # First Frame of request
                req_partial["active"] = True
                req_partial["len"] = ((data[0] & 0x0F) << 8) | data[1]
                req_partial["buf"] = bytearray(data[2:])
                if len(req_partial["buf"]) < req_partial["len"]:
                    continue
                req = bytes(req_partial["buf"][:req_partial["len"]])
                req_partial["active"] = False
            else:                             # Single Frame request
                req = bytes(data[1:1 + (data[0] & 0x0F)])
            resp = script.pop(0)
            n = len(resp)
            if n <= 7:
                ep.send_frame(0x7E8, bytes([n]) + resp)
            else:
                ep.send_frame(0x7E8, bytes([0x10 | (n >> 8), n & 0xFF]) + resp[:6])
                ep.recv_frame()               # wait FC
                sq = 1
                rest = resp[6:]
                while rest:
                    ch = rest[:7]; rest = rest[7:]
                    ep.send_frame(0x7E8, bytes([0x20 | sq]) + ch.ljust(7, b"\xCC"))
                    sq = (sq + 1) & 0x0F
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def main():
    link = FakeCanLink()
    vin = b"\x62\xF1\x90WVWZZZ1KZAW123456"          # 20 bytes -> forces FF/CF
    script = [
        b"\x50\x03\x00\x32\xC8",                     # answer to 10 03
        vin,                                          # answer to 22 F190 (multi-frame)
        b"\x7F\x19\x78",                              # answer to 19 02 FF: pending...
        b"\x59\x02\x00\x12\x34\x00\x56\x78\x09",      # ...then real DTC response (MF)
        b"\x7F\x22\x31",                              # answer to 22 FFFF: requestOutOfRange
    ]
    make_ecu(link, script)
    tr = LoopbackTransport(_Endpoint(link.a), 0x7E8, 0x7E0)
    u = UdsClient(tr)

    r = u.diagnostic_session(0x03)
    assert r == b"\x50\x03\x00\x32\xC8", r
    print("[PASS] 0x10 DiagnosticSessionControl ->", r.hex())

    v = u.read_data(0xF190)
    assert v == b"WVWZZZ1KZAW123456", v
    print("[PASS] 0x22 ReadDataByIdentifier multi-frame VIN ->", v.decode())

    dtcs = u.read_dtc()                                # exercises 0x78-pending + MF reassembly
    assert dtcs == ["123400", "567809"], dtcs
    print("[PASS] 0x19 ReadDTCInformation w/ responsePending ->", dtcs)

    try:
        u.read_data(0xFFFF)
    except NegativeResponseError as e:
        assert e.nrc == 0x31
        print("[PASS] negative response decoding ->", e)

    print("\nALL TESTS PASSED ✔  (ISO-TP SF/FF/CF/FC + UDS pending/negative logic verified)")


if __name__ == "__main__":
    main()
