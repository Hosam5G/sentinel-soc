# كيف تنشر Sentinel SOC على GitHub — دليل خطوة بخطوة

> دليل عملي بالعربي لنشر مشروعك كمشروع مفتوح المصدر بأمان.

---

## قبل أن تبدأ — تأكّد من هذه الأمور (مهم جداً)

### ⚠️ ١. لا ترفع أبداً الملفات السرّية
ملف `.gitignore` المرفق يمنع رفعها تلقائياً، لكن **تحقّق يدوياً** ألا ترفع:
- `sentinel.key` (مفتاح التشفير)
- `sentinel_*.json` (بياناتك وحساباتك)
- أي ملف فيه كلمات سر أو مفاتيح API

### ✍️ ٢. عدّل ملف LICENSE
افتح `LICENSE` وغيّر `[YOUR NAME HERE]` لاسمك الحقيقي.

### 📝 ٣. عدّل README
في `README.md`، أضف رابط مستودعك ومعلوماتك حيث يلزم.

---

## الطريقة الأولى: عبر موقع GitHub (الأسهل للمبتدئين)

### الخطوة ١: أنشئ حساباً ومستودعاً
1. سجّل في <https://github.com> (مجاني)
2. اضغط **+** أعلى اليمين ← **New repository**
3. اسم المستودع: `sentinel-soc` (أو ما تريد)
4. الوصف: `Privacy-first local security monitoring dashboard for Windows`
5. اختر **Public** (عام، ليراه الجميع)
6. **لا** تضف README أو .gitignore (عندك بالفعل)
7. اضغط **Create repository**

### الخطوة ٢: ارفع الملفات
1. في صفحة المستودع الجديد، اضغط **uploading an existing file**
2. اسحب كل ملفات المشروع (ماعدا الملفات السرّية — راجع .gitignore)
3. اكتب رسالة: `Initial release`
4. اضغط **Commit changes**

✅ تمّ! مشروعك الآن منشور.

---

## الطريقة الثانية: عبر Git (احترافية، موصى بها)

### الخطوة ١: ثبّت Git
نزّله من <https://git-scm.com/download/win> وثبّته.

### الخطوة ٢: جهّز المشروع محلياً
افتح PowerShell في مجلد مشروعك:

```bash
cd "E:\Equilibrium Design System"

# ابدأ مستودع Git
git init

# تأكّد أن .gitignore موجود (يحمي ملفاتك السرّية)
# ثم أضف الملفات
git add .

# تحقّق ماذا سيُرفع — تأكّد ألا ترى sentinel.key أو sentinel_*.json
git status

# سجّل أول نسخة
git commit -m "Initial release: Sentinel SOC v1.0"
```

### الخطوة ٣: اربطه بـ GitHub
أنشئ مستودعاً فارغاً على GitHub (الخطوة ١ من الطريقة الأولى، بدون أي ملفات)، ثم:

```bash
# اربط (استبدل USERNAME و REPO باسمك واسم مستودعك)
git remote add origin https://github.com/USERNAME/sentinel-soc.git

# ارفع
git branch -M main
git push -u origin main
```

سيطلب تسجيل الدخول — استخدم اسمك و **Personal Access Token** (لا كلمة السر).
لإنشاء token: GitHub ← Settings ← Developer settings ← Personal access tokens.

---

## بعد النشر — اجعله احترافياً

### ١. أضف وصفاً وكلمات مفتاحية (Topics)
في صفحة المستودع، اضغط ⚙️ بجانب About، وأضف topics مثل:
`security` `windows` `edr` `cybersecurity` `python` `flask` `privacy`

### ٢. أنشئ إصداراً (Release)
- المستودع ← **Releases** ← **Create a new release**
- Tag: `v1.0.0`
- العنوان: `Sentinel SOC v1.0`
- الوصف: لخّص الميزات الرئيسية
- هذا يعطي المستخدمين نقطة تحميل واضحة

### ٣. فعّل الإبلاغ عن الثغرات بأمان
- Settings ← Security ← فعّل **Private vulnerability reporting**
- ملف `SECURITY.md` المرفق سيُعرض تلقائياً

### ٤. أضف صوراً للـ README
ارفع لقطات شاشة للداشبورد — تجعل المشروع جذّاباً جداً.

---

## ✅ قائمة تحقّق نهائية قبل الرفع

- [ ] عدّلت `[YOUR NAME HERE]` في LICENSE
- [ ] `.gitignore` موجود في المجلد
- [ ] شغّلت `git status` وتأكّدت ألا ملفات سرّية ستُرفع
- [ ] حذفت أي `sentinel.key` أو `sentinel_*.json` من المجلد (أو تأكّدت أن
      .gitignore يتجاهلها)
- [ ] README يصف المشروع بوضوح + يوضّح أنه أداة مساعدة لا مضاد فيروسات
- [ ] requirements.txt موجود
- [ ] جرّبت تثبيته من الصفر في مجلد نظيف للتأكّد أنه يعمل

---

## نصائح لنجاح المشروع

1. **اكتب README جذّاباً** بصور — أول ما يراه الزائر.
2. **رُدّ على المشاكل (Issues)** بسرعة — يبني ثقة المجتمع.
3. **انشر عنه**: Reddit (r/cybersecurity, r/Python)، LinkedIn، X/Twitter.
4. **اقبل المساهمات** — pull requests تحسّن المشروع وتوسّع مجتمعه.
5. **حدّث بانتظام** — مشروع نشط يجذب أكثر.

بالتوفيق! 🚀
