# 📦 دليل الدمج — الملفات المحدّثة في هذا الإصدار

هذا الـ ZIP يحوي **الملفات التي عدّلتها أنا** + الملفات الأصلية. ادمجها مع مشروعك على
`E:\Equilibrium Design System` كالتالي.

## الملفات في الجذر (E:\Equilibrium Design System\)

| الملف | ضعه في | ملاحظة |
|-------|--------|--------|
| `dashboard_routes.py` | الجذر | **الخادم الكامل** (٦ محرّكات كشف، الأمان...) — استبدل القديم |
| `launcher.py` | الجذر | مُشغّل الـ exe |
| `sentinel.spec` | الجذر | إعداد PyInstaller |
| `build.bat` | الجذر | سكربت البناء |
| مجلد `tests/` | الجذر | ٨٥ اختبار |

## ملفات الواجهة (E:\Equilibrium Design System\dashboard\)

| الملف | ملاحظة |
|-------|--------|
| `index.html` | **مُحدَّث**: حُذف الوضع الفاتح + نظام خلفيات محلي (بلا CloudFront) |
| `api.js` | جسر الواجهة بالخادم (محدّث) |
| `layout.jsx` | حُذف زر الوضع الفاتح |
| `page-alerts-profile.jsx` | **مبدّل الخلفيات في الإعدادات** |
| `page-security-logs.jsx` | لوحة الكشف الحيّ + المعالجة |
| `page-overview.jsx` | نشاط حقيقي + تحذير CPU/RAM |
| `page-system-network-reports.jsx` | Geo-IP + تقارير |
| `ui.jsx` | مكوّنات مشتركة |

## 📚 مكتبات React محلياً (مطلوب — يصلح الشاشة السوداء)

السبب الذي جعل الواجهة لا تظهر: index.html كان يحمّل React/Babel من unpkg.com،
وسياسة الأمان (CSP) تمنع أي مصدر خارجي. الحل: نزّلها محلياً مرّة واحدة.

```powershell
cd "E:\Equilibrium Design System\dashboard"
mkdir vendor
curl -o vendor/react.js "https://unpkg.com/react@18.3.1/umd/react.development.js"
curl -o vendor/react-dom.js "https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js"
curl -o vendor/babel.min.js "https://unpkg.com/@babel/standalone@7.29.0/babel.min.js"
```

بعدها: صفر اتصال خارجي، تعمل بلا إنترنت، أمان كامل.

## 🎬 الفيديوهات (مهم!)

ملفاتك موجودة بالفعل في:
```
E:\Equilibrium Design System\dashboard\media\
  ├── bg-video-1.mp4   ✓ (موجود)
  └── bg-video-2.mp4   ✓ (موجود)
```

**ينقص ملف واحد** — الخلفية الأصلية. حمّلها بنفس المجلد باسم `bg-video-current.mp4`:
```powershell
cd "E:\Equilibrium Design System\dashboard\media"
curl -o bg-video-current.mp4 "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260315_073750_51473149-4350-4920-ae24-c8214286f323.mp4"
```
لو ما حمّلتها، خيار "الفيديو الأصلي" سيظهر أسود — لكن باقي الخلفيات (الفيديوهان + CSS) تعمل.

## ⚠️ ملفات لم ألمسها (تبقى كما هي عندك)

هذه موجودة على جهازك ولم أعدّلها — **لا تستبدلها**:
`styles.css`, `i18n.js`, `icons.jsx`, `premium-icons.jsx`, `charts.jsx`,
`motion.jsx`, `laptop-core.jsx`, `contrast-fix.css`, مجلد الخطوط.

## التشغيل

```cmd
cd "E:\Equilibrium Design System"
pip install flask cryptography psutil
python dashboard_routes.py
```
ثم افتح `http://127.0.0.1:8000` — اذهب لصفحة الإعدادات لتبديل الخلفية.

## بناء الـ exe

```cmd
build.bat
```
الناتج: `dist\Sentinel_SOC.exe` (سيتضمّن مجلد media تلقائياً).

## ما الجديد في هذا الإصدار

- ✅ **مبدّل خلفيات** في الإعدادات (٣ فيديو محلي + ٣ CSS) — بلا اتصال خارجي
- ✅ **حُذف الوضع الفاتح** (داكن فقط — الأنسب لأداة أمنية)
- ✅ **حُذف رابط CloudFront** من index.html — خصوصية محلية ١٠٠٪
- ✅ ٦ محرّكات كشف (عمليات/استمرارية/شبكة/حسابات/rootkit/سلامة ملفات)
- ✅ ٨٥ اختبار ناجح
