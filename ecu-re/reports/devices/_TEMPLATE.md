# Template — ملف تقني لجهاز (Technical Profile)

> يُنسخ إلى `devices/<name>.md` ويُملى جهازاً بجهاز. كل قسم إما **مُثبت** بمصدر، أو **مستنتَج** بدرجة ثقة، أو **⏳ مفتوح**. ممنوع الخلط بينهما.

## 0. الهوية
| البند | القيمة | المصدر/الدليل |
|---|---|---|
| الاسم التجاري | | تأكيد المالك + اختبار وصلة فردية |
| VID:PID | | `lsusb` |
| اسم المنتج في Windows/Linux | | (قد يكون مضللاً — وثّقه كما هو) |
| بنية الحماية | (مثال: Guardant dongle / لا شيء) | |

## 1. USB Device Descriptor (من `usb_id.py --json` أو `lsusb -vvv`)
```
bcdUSB          :
bDeviceClass    :
bcdDevice       :      ← حاسم لكشف FTDI المقنّع (الأصلي ≥0x0200)
iManufacturer   :
iProduct        :
iSerialNumber   :
MaxPower        :
```

## 2. Configuration / Interfaces / Endpoints
| Config | Interface (class/sub/proto) | Endpoints (addr/type/dir/maxp/interval) | التفسير الوظيفي |
|---|---|---|---|
| | | | |

## 3. الشريحة والـ Driver
- الشريحة المستنتجة: … (الثقة: مؤكد/مرجّح/مشكوك)
- Kernel driver عندك: … (`readlink /sys/bus/usb/devices/*/driver`)
- Windows driver: … (`.inf` name + provider من Device Manager)
- هل هناك احتكار kernel؟ (ftdi_sio/ch341/cdc_acm → يلزم unbind قبل pyusb/libusb مباشرة)

## 4. البرنامج المرتبط ومسار الاتصال
- Executables/DLLs: …
- طريقة الوصول: COM port / libusb raw / HID / J2534 passthru API / شبكة loopback
- سطر الأوامر أو إعدادات الاتصال: …

## 5. بنية البروتوكول (تُملأ من pcap/frida_hook)
- طبقة النقل: (FX2 bulk EP؟ FTDI MPSSE؟ AT-command فوق serial؟ UDS/ISO-TP؟)
- جدول الرسائل المكتشف: `opcode → معنى → مثال hex`
- تسلسل الجلسة: handshake → auth(seed/key?) → commands → checksum/CRC نوعه

## 6. ملاحظات وأخطاء مكتشفة
- …

## 7. حالة الإنجاز
- [ ] Descriptors · [ ] Endpoints · [ ] Driver · [ ] مسار برنامج · [ ] التقاط transactions · [ ] مواصفة بروتوكول
