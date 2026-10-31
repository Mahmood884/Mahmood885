# UPA-USB V1.3 — Cypress CY7C68013 EZ-USB FX2 (04B4:8613)

## 0. الهوية
| البند | القيمة | الدليل |
|---|---|---|
| الاسم التجاري | UPA-USB V1.3 (برمجة EEPROM/Flash I2C/SPI/95xxx/24xxx/93xx) | تأكيد المالك + اختبار وصلة فردية |
| VID:PID | `04B4:8613` | lsusb ✅ |
| اسم Linux المضلّل | "Cypress… EZ-USB FX2 USB 2.0 Development Kit" | هذا **افتراضي ROM** لـ FX2 عند PID=0x8613 — يثبت الشريحة ولا يصف المنتج |
| حماية | لا يوجد دونجل (البرنامج standalone) | ⏳ يُوثَّق |

## 1. لماذا 0x8613 مهم تقنياً
FX2 يحمل في ROM bootloader يدعم re-enumeration: أي firmware محمول على الـ device يعيد تقديم نفسه بـ VID/PID آخر بعد تحميله. عملياً الجهاز يعمل الآن بـ firmware مخصص من مصنع UPA، وWindows/Linux يرى هوية ROM الافتراضية فقط لأن descriptor strings لم تُغيَّر — وهذا **فرصة لنا**: واجهة FX2 Bulk معروفة جداً (EP2 OUT / EP6 IN، 512-byte bursts، وضع AUTOOUT/AUTOIN).

## 2. المتوقع من الفحص الكامل (ولم يُنفَّذ بعد)
```
bDeviceClass    : 00 (per-interface)   ← متوقع
bcdDevice       : 0000 أو قريب          ← متوقع من ROM؛ لو غيّره firmware = معلومات
Configuration     : interface 0, alt settings?
Endpoints         : متوقع 0x02 BULK OUT + 0x86 BULK IN (+ ربما 0x84 interrupt)
driver kernel     : unhandled → libusb مباشرة (لا cdc_acm هنا غالباً)
```

## 3. مسار الاتصال المتوقع للبرنامج
UPA-USB original (MiniPro?) يتصل عبر **libusb/winusb raw bulk** — لا COM port. الخطوات:
1. فتح الجهاز، set_configuration(1)، claim_interface(0).
2. إرسال أوامر برمجة bulk (تحديد البروتوكول هو هدفنا).
3. الاستجابة bulk IN بنفس الحجم أو أقصر.

## 4. خطة استخراج البروتوكول (مرتبة)
1. **Linux:** `sudo python3 tools/usb_id.py --vid 0x04B4 --json reports/data/upa_scan.json` → إثبات endpoints حقيقية لا متوقعة.
2. التقاط جلسات البرنامج↔الجهاز:
   - إذا يعمل برنامج الشركة عندك على Linux/wine: `modprobe usbmon; tcpdump -i usbmonN -w pcap/upa_read_24c02.pcap` أثناء قراءة EEPROM معلومة المحتوى (24C02 كل البايتات 0xFF أو pattern معروف).
   - **تلاعب ذكي:** بما أنك تعرف محتوى الـ EEPROM مسبقاً، استخرج العلاقة بين الأوامر والبيانات العائدة مباشرة (known-plaintext).
3. تحليل pcap: `python3 tools/usb_capture.py analyze pcap/upa_read_24c02.pcap --hex-dump` → جدول opcode→length→response.
4. إعادة تشغيل حي: `tools/usb_capture.py bulk --vid 0x04b4 --pid 0x8613 --replay upa_cmds.txt`.

## 5. بنود مفتوحة
- [ ] descriptors كاملة (بانتظار JSON منك).
- [ ] هل هناك string descriptors مخصصة (iProduct ≠ default)؟
- [ ] أول 20 أمر/رد موثقة → مواصفة `protocols/upa-fx2.md`.
