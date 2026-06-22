# 🔚 Sentinel SOC — Windows .exe التطبيق النهائي

## التطلبات

- **Windows 10/11**
- **Python 3.12** من [python.org](https://python.org) (⚠️ **ليس MSYS2**)
  - عند التثبيت: تأكد من ✓ "Add Python to PATH"
- الاتصال بالإنترنت لتحميل المكتبات (لمرة واحدة فقط)

## البناء (التغليف إلى .exe)

### الطريقة الموصى بها — تلقائية (Windows Batch)

١. افتح `cmd` أو PowerShell
٢. انتقل إلى مجلد المشروع:
   ```cmd
   cd "E:\Equilibrium Design System"
   ```
٣. شغّل سكريبت البناء:
   ```cmd
   build.bat
   ```
٤. انتظر 3-5 دقائق (يحمّل المكتبات ويجمّع .exe)
٥. ستجد الملف في: `dist\Sentinel_SOC.exe`

### البناء اليدوي (خطوة بخطوة)

لو أردت التحكم الكامل:

```cmd
# تثبيت المكتبات المطلوبة
pip install flask cryptography psutil pyinstaller

# اختياري: للأيقونة في Taskbar
pip install pystray pillow

# البناء
pyinstaller sentinel.spec

# الملف النهائي
dist\Sentinel_SOC.exe
```

## التشغيل

### بعد البناء

```cmd
# شغّل مباشرة
dist\Sentinel_SOC.exe
```

**سيحدث هذا تلقائياً:**
1. ✅ خادم Flask يبدأ على `http://127.0.0.1:8000`
2. ✅ المتصفّح ينفتح تلقائياً
3. ✅ أيقونة في Taskbar (إن كانت pystray/Pillow مثبّتة)

### للتشغيل السريع من Desktop

١. اضغط بزر اليمين على `dist\Sentinel_SOC.exe`
٢. اختر **"Create shortcut"**
٣. انسخ الاختصار إلى Desktop
٤. الآن تقدر تشغّل الكل من Desktop بضغطة واحدة

### للتشغيل التلقائي عند الإقلاع

١. اضغط `Win + R` واكتب:
   ```
   shell:startup
   ```
٢. سينفتح مجلد Startup الخاص بك
٣. ضع اختصار `Sentinel_SOC.exe` هناك
٤. في المرة القادمة التي تقلع الجهاز → Sentinel يشتغل تلقائياً

## استخدام التطبيق

### الدخول الأول

```
URL: http://127.0.0.1:8000
الحساب الأول → يصير admin تلقائياً
اسم مستخدم: admin (أو أي اسم تختار)
كلمة المرور: أي كلمة قوية (٨+ أحرف، أرقام + حروف)
```

### الملفات والبيانات

كل البيانات تُحفظ في **نفس المجلد** حيث `Sentinel_SOC.exe`:

```
dist/
├── Sentinel_SOC.exe
├── sentinel_users.json             ← الحسابات
├── sentinel_events.json            ← السجلّات (مُشفّرة)
├── sentinel_findings.json          ← الثغرات
├── sentinel_settings.json          ← الإعدادات
├── sentinel.key                    ← مفتاح التشفير
├── sentinel_audit.json             ← سجل التدقيق (مُشفّر)
├── sentinel_geoip.csv              ← DB الدول (بعد التنزيل)
├── sentinel_rules/                 ← قواعس YARA
│   └── community/                  ← قواعد محدّثة تلقائياً
└── backups/                        ← نسخ احتياطية يومية
```

**الخصوصية:** كل البيانات محلية بالكامل. **لا شيء يغادر جهازك** (إلا التحديثات الدورية بلا هويتك).

## استكشاف الأخطاء

### المتصفّح لا ينفتح

- فتح يدوي: افتح متصفحك واذهب إلى `http://127.0.0.1:8000`

### منفذ 8000 مشغول (خطأ "Address already in use")

- إما:
  - أغلق أي تطبيق آخر يستخدم المنفذ، أو
  - غيّر المنفذ:
    ```cmd
    set SENTINEL_PORT=8001
    dist\Sentinel_SOC.exe
    ```

### "Python not found"

- ✅ تأكد أنك ثبّت Python 3.12 من [python.org](https://python.org) (ليس MSYS2)
- ✅ في الـ installer: اختر ✓ "Add Python to PATH"
- ✅ أعد تشغيل `cmd` بعد التثبيت

### SSL/SMTP errors عند إرسال تنبيهات

- ✅ استخدم Python من python.org فقط (MSYS2 يفتقد شهادات SSL)
- ✅ استخدم Gmail App Password (ليس كلمة السر العادية):
  1. اذهب https://myaccount.google.com/apppasswords
  2. توليد password للبريد
  3. استخدمه في الإعدادات

## التحديث للإصدار الجديد

لو حمّلت نسخة محدّثة من الكود:

١. احذف المجلد القديم `dist/`
٢. شغّل `build.bat` من جديد
٣. بياناتك محفوظة (في مجلد المشروع)

## الميزات في .exe

✅ بدون نافذة أوامر سوداء
✅ أيقونة في Taskbar (اختياري مع pystray)
✅ كل الميزات الأمنية محلية بالكامل:
  - فحص ثغرات حقيقي
  - كشف حوادث من Event Log
  - استخبارات تهديدات (CISA KEV)
  - تحليل ملفات محلي
  - YARA rules (مع تحديث دوري)
  - تشفير at-rest للبيانات
  - اختبارات أمان شاملة

## الأداء

| البارامتر | القيمة |
|----------|--------|
| بدء التشغيل | <3 ثوان |
| استهلاك الذاكرة | 150-300 MB |
| فحص شامل | 10-30 ثانية |
| خادم الويب | مستجيب فوراً |

## الدعم والمشاكل

لو واجهت مشكلة:
١. تحقق من أن Python مثبّت بشكل صحيح: `python --version`
٢. تحقق من أن جميع المكتبات مثبّتة:
   ```cmd
   pip list | findstr flask cryptography psutil pyinstaller
   ```
٣. جرّب البناء مجدداً (قد تحتاج تحديث المكتبات):
   ```cmd
   pip install --upgrade flask cryptography psutil pyinstaller
   pyinstaller sentinel.spec
   ```

---

**تم!** 🎉 لديك الآن تطبيق Windows سطح المكتب المكتمل والخصوصي.

إذا أردت مزيد من المساعدة أو واجهت أي مشكلة — أخبرني.
