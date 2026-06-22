# كيفية تثبيت هذا التحديث بشكل صحيح

> اقرأ هذا أولاً لتجنّب مشكلة «dashboard داخل dashboard».

## البنية الصحيحة للمشروع

يجب أن يكون مشروعك هكذا بالضبط:

```
E:\Equilibrium Design System\          ← مجلد المشروع (الجذر)
│
├── dashboard_routes.py                 ← الخادم (ضعه في الجذر)
├── launcher.py                         ← (الجذر)
├── sentinel.spec                       ← (الجذر)
├── build.bat                           ← (الجذر)
├── test_protection.ps1                 ← (الجذر)
├── requirements.txt, README.md, ...    ← (الجذر)
│
├── dashboard\                          ← مجلد واحد فقط
│   ├── api.js
│   ├── index.html
│   ├── layout.jsx
│   ├── ui.jsx
│   ├── charts.jsx
│   ├── contrast-fix.css
│   ├── page-overview.jsx
│   ├── page-security-logs.jsx
│   ├── page-system-network-reports.jsx
│   ├── page-alerts-profile.jsx
│   │
│   └── (ملفاتك الخاصة التي لا ألمسها):
│       styles.css, i18n.js, icons.jsx, premium-icons.jsx,
│       motion.jsx, laptop-core.jsx, vendor\, media\
│
├── fonts\                              ← خطوطك (الجذر)
├── tests\                              ← الاختبارات
└── (ملفات بيانات تُنشأ تلقائياً: sentinel_*.json)
```

## ⚠️ تجنّب الخطأ الشائع: dashboard داخل dashboard

إذا فككت ملف الـ ZIP **داخل** مجلد `dashboard` الموجود، ستحصل على:
```
dashboard\dashboard\api.js   ← خطأ!
```
بدل:
```
dashboard\api.js             ← صحيح
```

## طريقة التثبيت الصحيحة

### الخطوة ١: أوقف الخادم تماماً
أغلق نافذة الخادم، أو اضغط Ctrl+C فيها.

### الخطوة ٢: فكّ الـ ZIP في مكان مؤقّت
فكّ `Sentinel_SOC_Final.zip` في مجلد جديد مؤقّت (مثل سطح المكتب)، **ليس** داخل مشروعك مباشرة.

### الخطوة ٣: انسخ الملفات لأماكنها الصحيحة
- ملفات الجذر (`dashboard_routes.py`, `launcher.py`, `sentinel.spec`, إلخ) → انسخها إلى `E:\Equilibrium Design System\` (استبدل القديمة)
- محتويات مجلد `dashboard\` من الـ ZIP → انسخها إلى `E:\Equilibrium Design System\dashboard\` (استبدل القديمة، **لا** تنشئ مجلداً جديداً)

### الخطوة ٤: تحقّق من البنية
في PowerShell:
```powershell
cd "E:\Equilibrium Design System"
Test-Path "dashboard\dashboard"
```
- يجب أن يظهر **`False`** (لا يوجد dashboard مكرّر)
- لو ظهر `True`، انقل الملفات من `dashboard\dashboard\` إلى `dashboard\` واحذف المجلد المكرّر

```powershell
dir dashboard\api.js
```
- يجب أن يظهر الملف (دليل أن البنية صحيحة)

### الخطوة ٥: شغّل الخادم
```powershell
$env:SENTINEL_PORT=8765
python dashboard_routes.py
```
ثم افتح <http://127.0.0.1:8765> واضغط `Ctrl+Shift+R`.

## الملفات التي أحدّثها أنا (استبدلها)

**في الجذر:** `dashboard_routes.py`, `launcher.py`, `sentinel.spec`, `build.bat`, `test_protection.ps1`

**في dashboard\:** `api.js`, `index.html`, `layout.jsx`, `ui.jsx`, `charts.jsx`, `contrast-fix.css`, `page-overview.jsx`, `page-security-logs.jsx`, `page-system-network-reports.jsx`, `page-alerts-profile.jsx`

## الملفات التي لا ألمسها (تبقى كما هي عندك)

`styles.css`, `i18n.js`, `icons.jsx`, `premium-icons.jsx`, `motion.jsx`, `laptop-core.jsx`, مجلد `fonts\`, مجلد `dashboard\vendor\`, مجلد `dashboard\media\`

> هذه ملفاتك الخاصة (التصميم، الخطوط، المكتبات). لا أرسلها في الـ ZIP حتى لا أكتب فوقها.

## ما الجديد في هذا التحديث

- إصلاح ثغرة أمنية: حماية قائمة المستخدمين و endpoints التصدير بالمصادقة
- إزالة قيم موك-أب (LIVE، vitals الوهمية)
- خط الأساس السلوكي يُحفظ عند إغلاق التطبيق
- زر «آمن» للاستمرارية يؤكّد ويختفي
- مؤشّر حالة النموذج صادق (متصل/يحلّل/غير متصل)
- تقييد رسائل الأخطاء لمنع تسريب المسارات
- ٩ قواعد YARA (بدل ٤)، تجميع مقاوم للأخطاء
- الـ exe لا يفتح نوافذ PowerShell، يضمّ الخطوط
