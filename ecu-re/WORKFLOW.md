# سير العمل — فريق ECU-RE

**التسلسل:** المالك (أنت) ← Hermes ← qoder (هذا العامل)

## قواعد التشغيل
1. كل مهمة تصل كخطوة واحدة قابلة للتحقق: أمر يُنفَّذ، أو ملف يُنتَج، أو نتيجة اختبار خضراء.
2. لا تعليمات مبنية على افتراضات عن حالة /workspace — كل جولة تبدأ بفحص فعلي (`git log`، تشغيل الاختبارات).
3. إذا وصلتك تعليمات خاطئة أو غير مجدية أو هناك أفضل منها → **أبدي الرأي قبل التنفيذ**، مع البديل المقترح. نحن فريق واحد؛ الصمت على خطأ مكلف.
4. أي تغيير يمر بـ: تنفيذ → تشغيل تحقق → commit برسالة توضيحية.

## حالة المشروع (آخر تحقق: 2026-11-01 — جرد المرحلة + ملفات البروفيل)
| الطبقة | الأداة | الحالة |
|---|---|---|
| 1. Hardware ID | tools/usb_id.py | ✅ يعمل (مختبَر على بيئة بلا USB — fallback sysfs سليم) |
| 2. USB/Driver RE | tools/usb_capture.py | ✅ HID raw + pcap analyzer جاهز، **يحتاج بيانات حقيقية** |
| 3. Protocol RE | tools/proto_find.py | ✅ UDS/CAN/K-line/ELM327/pattern-ready؛ pattern يقبل JSON-array وJSON-lines وhex-dump |
| 3b. In-process interception | tools/frida_hook.py | ✅ **جديد ومُختبَر E2E**: اعتراض serial/HID/net/TLS/crypto داخل عملية برنامج الشركة؛ يلتقط seed/key قبل التشفير |
| 4. Independent SW | tools/uds_lib.py | ✅ ISO-TP+UDS كامل — test_uds.py 4/4 PASS |

**تبعيات frida:** `pip install frida capstone` (frida 17.x — الكود متوافق مع إزالة Module.findExportByName(null,...)).

## العنقدين الحقيقيين (لا يمكن حلها من سحابتي)
1. **لا USB لدي** — هذه البيئة لا تملك `/dev/bus/usb`. تحديد شرائح أجهزتك يتطلب تشغيل `usb_id.py` عندك وإرسال JSON.
2. **لا بيانات التقاط** — تحليل بروتوكولات برامج الشركات يبدأ من pcap/DOM API hook عندك؛ أدواتي تنتظرها في `pcap/`.

## ملاحظات فنية محفوظة
- أجهزة صينية offline بدون اشتراك = غالباً: CP210x/CH340 مقنّعة بـ VID FTDI، أو STM32 HID (0483)، أو نسخ LL503/KT200/ACDP.
- seed/key لأجهزة Xhorse/Yanhua يعتمد ملفات local calculators — كشفها من reverse الـ DLLs وليس الشبكة.
- read_dtc بصيغة ISO14230-4 (بدون availability byte) — مصحَّح ومثبت بالاختبار.


**جولة 2026-11-01 (التقرير المرسل من المالك):**
- `reports/inventory.md` — الجرد الرسمي الست وحدات + القواعد الأربع المستقرة + بروتوكول جمع البيانات.
- `reports/devices/*.md` — ملف تقني لكل جهاز (upa/galletto/j2534/ch341a/ktmflash) بحالة مثبت/مستنتج/مفتوح، + `_TEMPLATE.md`.
- `usb_id.py`: KNOWN_CHIPS أُضيفت لها معرّفات الأجهزة الخمسة المؤكدة؛ **bcdDevice أصبح يُقطف في pyusb وsysfs** (سلاح حسم FTDI المقنّع للغاليتو).
- ملاحظة نطاق 2000–2021 وأثرها: K-line→UDS-CAN→DoIP كأولوية طبقة 3.
