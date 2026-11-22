# KTMFLASH Dongles — Aktiv Guardant (0A89:0009)

## الحالة المعروفة (مؤكدة بالاختبار المادي)
- وحدتان فيزيائيتان مستقلتان تحملان نفس `0A89:0009` (ظهرتا كـ Device 049 و050 عند التوصيل معاً).
- الشريحة: Aktiv Guardant RUSB — هذا **dongle حماية** وليس واجهة برمجة سيارات.
- البرامج المرتبطة: KTMFLASH 1.21-12 و KTMFLASH "67 in 1". المنظومة إجمالاً 3–4 دونجلات؛ **الوحدات #3/#4 لم تُجرد بعد**.

## ماذا يعني هذا هندسياً (قراءة صحيحة للدور)
برنامج KTMFLASH لا "يتكلم" مع Guardant بأوامر ECU — بل:
1. التطبيق يستدعي Guardant API محلياً (غالباً `guardant.dll`/`rusbapi.dll`) لعمل **challenge/response** مع الدونجل.
2. إذا نجح القفل، يفتح التطبيق منطق الـ flash نفسه ويتحدث مع الواجهة الفعلية (J2534/serial/HID حسب بقية العتاد).
3. لذلك بروتوكول الدونجل = بروتوكول قفل خاص بالأktiv، ومنفصل تماماً عن بروتوكولات ECU.

## خطة العمل المقترحة (بدون أي التصاق بالعتاد أولاً)
### أ. مسح السطح (Windows host الذي يعمل عليه KTMFLASH)
```powershell
# ابحث عن DLLs الخاصة بالحماية داخل مجلد KTMFLASH
dir /s /b C:\KTMFLASH* | findstr /i "guardant rusb rusba vendor"
# راقب أي ملفات يفتحها البرنامج عند التشغيل (Procmon: filter Process Name)
```
### ب. اعتراض استدعاءات الحماية (الأداة الجاهزة: tools/frida_hook.py)
```bash
python3 tools/frida_hook.py spawn --exe "C:/KTMFLASH/KTMFLASH.exe" --modules guardant,rusb
```
- الهدف الأول: **هل الشبكة المحلية تدخل في المعادلة؟** (Guardant يدعم أحياناً license server على TCP 28000+؛ الأجهزة offline تعني غالباً local-only challenge).
- الهدف الثاني: التقاط payloads الـ challenge/response بين DLL↔driver↔dongle عبر hooks على CreateFile/DeviceIoControl (`\\.\RUSBX`-style device interface).
### ج. فحص واجهة USB الخام (Linux)
```bash
sudo python3 tools/usb_id.py --vid 0x0A89 --json reports/data/guardant_scan.json
# ثم حاول قراءة descriptors كاملة — انتبه: قد ترفض الوحدة طلبات غير موقعة
```

## ما NOT نفعله (حد صريح)
لا نكتب emulator للدونجل ولا نكسر التوقيع — نطاقنا: فهم المسار وتوثيقه، وبناء أدواتنا المستقلة التي تتعامل مع **ECU/TCU نفسها** عبر واجهاتنا (UPA/Galletto/J2534)، بحيث لا تحتاج KTMFLASH أصلاً. إذا اتضح أن وظائف معينة مقفلة خلف Guardant حصراً، نقرر لاحقاً وبشفافية.

## بنود مفتوحة
- [ ] تجريد الدونجل #3/#4 وإثبات هل هي Guardant أخرى أم واجهات مختلفة.
- [ ] قائمة DLLs الفعلية + أسماء exports (Dependency Walker / `dumpbin /exports`).
- [ ] أول transcript لـ DeviceIoControl challenge/response (frida).
- [ ] bcdDevice + string descriptors للوحدتين (لإثبات الاستقلالية رقمياً لا بالـ device number فقط).
