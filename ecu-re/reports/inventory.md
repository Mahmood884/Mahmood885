# جرد الأجهزة — Hardware Inventory (verified by physical test)

**آخر تحديث:** 2026-11-01 · **المرجع:** تقرير المرحلة 31/10/2026 · **منهجية:** جهاز واحد لكل اختبار، نفس المنفذ الفيزيائي، مقارنة delta في `lsusb`

| # | الجهاز | VID:PID | الشريحة (استنتاج أولي) | حالة الهوية | ملف تقني |
|---|--------|---------|------------------------|-------------|----------|
| 1 | UPA-USB V1.3 | `04B4:8613` | Cypress CY7C68013 EZ-USB FX2 | ✅ مؤكد بالاختبار المادي | `devices/upa-usb-v13.md` |
| 2 | FGTech Galletto 4 | `0403:DAAD` | FTDI FT232R **أو مقنَّعة (CP210x/CH340) — لم يُحسم** | ✅ منتج مؤكد / ⚠ شريحة غير مثبتة | `devices/galletto-4.md` |
| 3 | PCM Super J2534 | `20A2:0001` | Vendor-specific (Emotek/Tactiq-style J2534) | ✅ مؤكد — الاسم التجاري لا قاعدة البيانات | `devices/pcm-super-j2534.md` |
| 4 | CH341A programmer | `1A86:5512` | QinHeng CH341 (وضع EPP/MEM/I2C) | ✅ شريحة مؤكدة / ⚠ ربطه بوحدته النهائية يحتاج تأكيداً | `devices/ch341a.md` |
| 5 | KTMFLASH Dongle #1 | `0A89:0009` | Aktiv Guardant RUSB (dongle protection) | ✅ مؤكد | `devices/ktmflash-dongles.md` |
| 6 | KTMFLASH Dongle #2 | `0A89:0009` | Aktiv Guardant RUSB | ✅ مؤكد — وحدتان مستقلتان بنفس المعرف (Device 049/050) | `devices/ktmflash-dongles.md` |
| ? | KTMFLASH dongle #3/#4 | **مجهول** | — | ⏳ لم تُجرد بعد | `devices/ktmflash-dongles.md` |

**برمجيات مرتبطة:** KTMFLASH 1.21-12 · KTMFLASH "67 in 1" · برامج UPA/Galletto/J2534 passthru الخاصة بالشركة.

## قواعد ثابتة خرجت بها المرحلة (لا تنتهك لاحقاً)
1. **اسم Linux ≠ اسم المنتج** — مثال: UPA-USB ظهر باسم "EZ-USB FX2 Development Kit". لا نستنتج تجارة من descriptor.
2. **VID:PID ≠ هوية وحدة فيزيائية** — دونقلا Guardant تشابها تماماً؛ التمييز فقط بـ bus/device path أو serial number أو اختبار فردي.
3. **قواعد بيانات VID/PID مصدر شك لا يقين** — مثال: `20A2:0001` ملوث بتسمية "SM2 Pro" خارجية؛ الاختبار المادي + تأكيد المالك هو المرجع.
4. **VIDs معروفة يجب الحذر من انتحالها في الأجهزة الصينية:** `0403` (FTDI غالباً مقنَّع)، `1A86` (حقيقي عادةً)، `04B4` (Cypress حقيقي عادةً لأن FX2 clone يصعب توثيقه)، `0A89` (Aktiv — حقيقي، الحماية نفسها).

## الفجوات المفتوحة (ما لم يُنجز بعد)
- [ ] Device Descriptors كاملة (bDeviceClass, configurations, interfaces, endpoints, power) لأي جهاز.
- [ ] Kernel driver فعلي لكل جهاز (`lsusb -t`, `/sys/bus/usb/drivers/`).
- [ ] الوحدات المتبقية من KTMFLASH (3 أو 4 إجمالاً؛ حددنا 2).
- [ ] هل Galletto 4 يستخدم FT232R أصلياً؟ (يتطلب `bcdDevice` فحص — انظر بروتوكول العمل أدناه).

## بروتوكول جمع البيانات (يُنفَّذ عندك على Linux host متصل بالأجهزة)
```bash
# 1. مسح كامل موثّق لكل جهاز (وصلة واحدة لكل تشغيل)
sudo python3 tools/usb_id.py --json reports/data/scan_$(date +%F_%H%M).json

# 2. descriptors خام + التسلسل الشجري + drivers
lsusb -vvv > reports/data/lsusb_vvv.txt
lsusb -t   > reports/data/lsusb_tree.txt
for d in /sys/bus/usb/devices/*/; do echo "== $d"; readlink -f $d/driver 2>/dev/null; cat $d/product $d/serial 2>/dev/null; done > reports/data/sysfs_map.txt

# 3. لتمييز دونقلي Guardant المتطابقين: bus-port path لكل وصلة
udevadm info -q path -n /bus/usb/devices/$(lsusb | grep 0a89:0009 | head -1 | awk '{print $2"/"$4}' | tr -d ':') 
```
ثم تُرفع الملفات إلى `reports/data/` وتُملأ ملفات `devices/*.md` واحداً واحداً.

## نطاق الموديلات 2000–2019 (+امتداد 2021) — أثره البروتوكولي
- **2000–2004 تقريباً:** K-line ISO9141/ISO14230 (KP201/KWP2000) — Galletto/ELM-style يكفي؛ لا DoIP، ولا CAN على كل الشبكات.
- **2005–2017:** UDS on ISO15765-2 (CAN 500k/1M) هو العمود الفقري — `uds_lib.py` جاهز مع backends.
- **2018–2021 امتداد:** UDS on IP = **DoIP** في ماركات عديدة (VW/Audi/BMW/Mercedes newer gateways) + SecOC في بعض المسارات. أجهزة J2534 مثل PCM Super قد تحمل DoIP عبر Ethernet passthru — يُتحقق من descriptors ثم نقرر هل نضيف `doip_lib.py` للطبقة الرابعة.
- لذلك أولويات الطبقة 3 المنطقية: **K-line/Galletto أولاً (أقدم الموديلات وأسهلها)، ثم J2534-CAN UDS، ثم DoIP لاحقاً**.

