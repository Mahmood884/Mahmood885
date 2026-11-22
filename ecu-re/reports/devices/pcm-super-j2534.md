# PCM Super J2534 — 20A2:0001

## 0. الهوية (حسمت بالاختبار المادي ضد قاعدة البيانات)
- المنتج: **PCM Super J2534** passthru interface. تأكيد المالك بعد أن أظهرت قواعد بيانات خارجية تسمية "SM2 Pro" لنفس المعرف — وهذا مثال محفوظ في المشروع: **قاعدة البيانات لا تحسم، الوصلة الفردية تحسم**.
- `0x20A2` = VID مستعمل من عائلة أجهزة Emotek/J2534 re-branders؛ PID 0x0001 عام جداً ⇒ أي استنتاج إضافي ممنوع حتى descriptors.

## 1. ما يعنيه "J2534" هندسياً
الجهاز يقدّم نفسه عبر **PassThru API** (Windows: DLL بمواصفة SAE J2534 / ISO 22900). أي برنامج دياجنوستيك يستدعي:
```
PASSTHRU_OPEN_DEVICE → SET_PARAMS(ISO15765/CAN, baud) → PASSMSG (frames) → PASSREC
```
والـ DLL تترجم هذه الاستدعاءات إلى أوامر USB vendor-specific داخل الجهاز. **مستوى USB الخام غالباً libusb/winusb bulk أو interrupt endpoints** — وليس serial قياسي.

## 2. خطة البروفيلينغ
### Linux (أولاً، أرخص)
```bash
sudo python3 tools/usb_id.py --vid 0x20A2 --json reports/data/j2534_scan.json
lsusb -vvv -d 20a2:0001        # endpoints + class codes
```
### اعتراض مستوى J2534 API (الأعلى قيمة — هنا تعيش الأوامر بصيغة شبه معيارية)
- على Windows host: frida_hook على `passng*.dll` / الـ DLL الخاصة بالجهاز (`PcmSuper?`) intercepting exports: PassThruOpen/Connect/MsgSend/MsgRec — نلتقط **كل UDS frame كما يراه الجهاز قبل التغليف USB**.
- هذا يعطينا طبقة 3 مجاناً لأن J2534 يحمل UDS/CAN فوقه مباشرة.

## 3. فرصة الطبقة الرابعة (استقلال Linux)
مشروع مفتوح المصدر موجود كمسار مرجعي نظيف بدل إعادة اختراع الـ passthru:
- **opendash / python-can j2534 bindings**، والأهم: إذا كشفنا wire-format بين DLL↔جهاز، نستطيع كتابة backend لـ **uds_lib.py يتكلم libusb مباشرة** بدون أي J2534 DLL — هدف مشروعنا النهائي.
- بديل فوري للاختبار الحي: `python-can` + SocketCAN إن ظهر الجهاز كـ kvaser/peak-like عند loading driver مناسب (⏳ يُتحقق بعد descriptors).

## 4. بنود مفتوحة
- [ ] descriptors كاملة + endpoints.
- [ ] اسم DLL الج2534 الفعلية وexports جدولها (`dumpbin /exports`).
- [ ] transcript أول جلسة PassThruMsgSend→USB bulk (frida + usbmon متزامنان لإثبات التعيين).
- [ ] هل يدعم DoIP؟ (موديلات 2018–2021 تحتاجه أحياناً؛ انظر ملاحظة النطاق الزمني أسفل inventory).
