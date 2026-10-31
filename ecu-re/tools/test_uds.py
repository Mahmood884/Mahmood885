#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_uds.py — اختبار وحدة ISO-TP/UDS بدون عتاد فعلي (بدون SocketCAN)
=====================================================================
يستبدل CANTransport بـ FakeIsoTp بنقل موثوق فوق queue.Queue (اتجاهان منفصلان،
بلا echo/broadcast كما في socketpair أو vcan)، مع fake ECU في thread يجيب
من script متسلسل. يغطي:
  SF->SF, FF/FC/CF multi-frame, NRC 0x78 responsePending, negative responses.

التشغيل:   python3 test_uds.py
"""
import sys, os, time, threading
from collections import deque
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uds_lib import UdsClient, NegativeResponseError


class FakeLink:
    """نقل ثنائي الاتجاه موثوق: كل اتجاه queue منفصل (لا echo ولا broadcast)."""
    def __init__(self):
        self.t2e = deque()   # tester -> ecu frames  (can_id, data)
        self.e2t = deque()   # ecu -> tester frames
        self.cv_t = threading.Condition()  # signaled when e2t gets data
        self.cv_e = threading.Condition()  # signaled when t2e gets data

    def send_tester(self, cid, data):
        with self.cv_e:
            self.t2e.append((cid, bytes(data)))
            self.cv_e.notify()

    def send_ecu(self, cid, data):
        with self.cv_t:
            self.e2t.append((cid, bytes(data)))
            self.cv_t.notify()

    def recv_tester(self, timeout=2.0):
        deadline = time.time() + timeout
        with self.cv_t:
            while not self.e2t:
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError("tester rx timeout")
                self.cv_t.wait(left)
            return self.e2t.popleft()

    def recv_ecu(self, timeout=5.0):
        deadline = time.time() + timeout
        with self.cv_e:
            while not self.t2e:
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError("ecu rx timeout")
                self.cv_e.wait(left)
            return self.t2e.popleft()


class FakeIsoTp:
    """واجهة مطابقة لـ CANTransport.send/recv لكن فوق FakeLink."""
    def __init__(self, link, rx_id, tx_id):
        self.link, self.rx_id, self.tx_id = link, rx_id, tx_id

    def send(self, payload):
        n = len(payload)
        if n <= 7:
            self.link.send_tester(self.tx_id, bytes([n]) + payload)
        else:
            self.link.send_tester(self.tx_id,
                                  bytes([0x10 | (n >> 8), n & 0xFF]) + payload[:6])
            seq, off = 1, 6
            while off < n:
                chunk = payload[off:off + 7]
                self.link.send_tester(self.tx_id, bytes([0x20 | (seq & 0xF)]) + chunk)
                seq = (seq + 1) & 0xF
                off += 7

    def recv(self, timeout=2.0):
        buf, total, expect_sn = bytearray(), None, 1
        while True:
            cid, data = self.link.recv_tester(timeout)
            if cid != self.rx_id:
                continue
            ftype = data[0] >> 4
            if ftype == 0:
                return bytes(data[1:1 + (data[0] & 0x0F)])
            elif ftype == 1:
                total = ((data[0] & 0x0F) << 8) | data[1]
                buf += data[2:]
                self.link.send_tester(self.tx_id, bytes([0x30, 0x00, 0x00]))  # FC CTS
            elif ftype == 2:
                sn = data[0] & 0x0F
                assert sn == expect_sn, f"CF seq error {sn}!={expect_sn}"
                expect_sn = (expect_sn + 1) & 0x0F
                buf += data[1:]
                if total and len(buf) >= total:
                    return bytes(buf[:total])
            # ftype==3 (FC from ECU to our request) handled by ECU side; ignore here


def iso_tp_send(link, cid, payload):
    """Helper used by the fake ECU to transmit an ISO-TP message."""
    n = len(payload)
    if n <= 7:
        link.send_ecu(cid, bytes([n]) + payload)
    else:
        link.send_ecu(cid, bytes([0x10 | (n >> 8), n & 0xFF]) + payload[:6])
        # wait for tester's Flow Control
        while True:
            fc_id, fc = link.recv_ecu()
            if fc_id == 0x7E0 and (fc[0] >> 4) == 3:
                break
        seq, off = 1, 6
        while off < n:
            chunk = payload[off:off + 7]
            link.send_ecu(cid, bytes([0x20 | (seq & 0xF)]) + chunk)
            seq = (seq + 1) & 0xF
            off += 7


def make_ecu(link, script, delay_before_final=0.15):
    """fake ECU: يقرأ الطلبات كاملة ثم يجيب من script بالتتابع.
    إذا كانت الإجابة 7F xx 78 (pending) ينتظر قليلاً ثم يرسل الإجابة التالية."""
    def run():
        partial = {"active": False, "len": 0, "buf": bytearray()}
        while script:
            cid, data = link.recv_ecu()
            if cid != 0x7E0:
                continue
            ftype = data[0] >> 4
            if ftype == 3:                      # tester FC — consumed inside iso_tp_send
                continue
            if ftype == 1:
                partial["active"] = True
                partial["len"] = ((data[0] & 0x0F) << 8) | data[1]
                partial["buf"] = bytearray(data[2:])
                if len(partial["buf"]) < partial["len"]:
                    continue
                req = bytes(partial["buf"][:partial["len"]]); partial["active"] = False
            elif ftype == 2:
                if not partial["active"]:
                    continue
                partial["buf"] += data[1:]
                if len(partial["buf"]) < partial["len"]:
                    continue
                req = bytes(partial["buf"][:partial["len"]]); partial["active"] = False
            else:
                req = bytes(data[1:1 + (data[0] & 0x0F)])
            resp = script.pop(0)
            iso_tp_send(link, 0x7E8, resp)
            # handle pending chain: keep sending next scripted frame as final answer
            while resp.startswith(b"\x7f") and len(resp) == 3 and resp[2] == 0x78 and script:
                time.sleep(delay_before_final)
                resp = script.pop(0)
                iso_tp_send(link, 0x7E8, resp)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def main():
    link = FakeIsoTpLink = FakeLink()
    vin = b"\x62\xF1\x90WVWZZZ1KZAW123456"           # 20 bytes -> forces FF/CF
    script = [
        b"\x50\x03\x00\x32\xC8",                     # answer to 10 03
        vin,                                          # answer to 22 F190 (multi-frame)
        b"\x7F\x19\x78",                              # answer to 19 02 FF: pending...
        b"\x59\x02\x12\x34\x00\x0A\x56\x78\x09\x02",  # ...then real DTC response (MF): 2x (DTC+status)
        b"\x7F\x22\x31",                              # answer to 22 FFFF: requestOutOfRange
    ]
    make_ecu(link, script)
    tr = FakeIsoTp(link, rx_id=0x7E8, tx_id=0x7E0)
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
        raise AssertionError("expected NegativeResponseError")
    except NegativeResponseError as e:
        assert e.nrc == 0x31
        print("[PASS] negative response decoding ->", e)

    print("\nALL TESTS PASSED ✔  (ISO-TP SF/FF/CF/FC + UDS pending/negative logic verified)")


if __name__ == "__main__":
    main()
