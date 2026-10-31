# FGTech Galletto 4 — FTDI-style (0403:DAAD)

## 0. الهوية
- المنتج مؤكد بالاختبار المادي وتأكيد المالك: **FGTech Galletto 4** (ECU/TCU flash، دعم Motronic/Bosch/Siemens/VDO، وضع K-line + CAN + bench).
- المعرف `0403:DAAD`: VID شركة FTDI لكن PID غير قياسي (قياسي FTDI: 6001/6010/6011…) ⇒ **إعادة تعيين EEPROM/custom** أو مقنَّع بالكامل.

## 1. السؤال المفتوح الحاسم: FT232R أصلي أم CP210x/CH340 مقنّع؟
الأدلة الرقمية التي تحسمها (كلها متاحة من فحص واحد):
| الدليل | FT232R أصلي | مقنّع (CP210x/CH340) |
|---|---|---|
| `bcdDevice` | ≥ 0x0200 (إصدار روم FTDI) | عادة 0x0100 أو قِيَم عشوائية |
| Modem status bytes (FTDI SIO cmd 0x01) | يستجيب بـ 0x01 0x01 + line state | لا يستجيب أو يستجيب بشكل مختلف |
| FTDI vendor requests (0x0B/0x03 MPSSE-like) | OK | stall/error |
| driver kernel المقبول | ftdi_sio | ftdi_sio يفشل → usbtiny/generic |
| سلوك `echo > ttyUSBx` | طبيعي | قد يظهر باود ريت غير قابل للتغيير |

**الإجراء:** `lsusb -vvv -d 0403:daad` + `sudo python3 tools/usb_id.py --vid 0x0403 --json reports/data/galletto_scan.json` ثم نقارن bcdDevice.

## 2. طبقة النقل المتوقعة (بعد حسم الشريحة)
غالبية Galletto-style تعمل كـ **COM port افتراضي** (ftdi_sio → /dev/ttyUSBx @ baud ثابت مثل 38400/115200)، وبروتوكول التطبيق فوقه ليس AT بل binary framing خاص بـ FGTool. لذلك:
1. إن ظهر كـ serial: `sudo python3 tools/proto_find.py kline --device /dev/ttyUSB0 --baud 38400 --sniff 30s` أثناء تشغيل FGTool (أو hook frida على CreateFile("\\\\.\\COM") ).
2. التقاط أفضل مصدر: FGTool.exe ↔ COM — عبر frida_hook (serial mode) لأنه يرى الـ plaintext قبل التشفير إن وُجد.

## 3. بنود مفتوحة
- [ ] حسم الشريحة بـ bcdDevice/vendor requests.
- [ ] Windows .inf الفعلي المستخدم (Galletto installer folder).
- [ ] أول transcript ثنائي للأوامر (وضع K-line على بوردة معروفة مثل EDC16 — known target).
- [ ] توثيق وضع الـ bench/CAN pins (من PCB لاحقاً إن لزم).
