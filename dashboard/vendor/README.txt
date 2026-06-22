ضع مكتبات React هنا (نزّلها مرّة واحدة):

  cd "E:\Equilibrium Design System\dashboard"
  mkdir vendor
  curl -o vendor/react.js     "https://unpkg.com/react@18.3.1/umd/react.development.js"
  curl -o vendor/react-dom.js "https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js"
  curl -o vendor/babel.min.js "https://unpkg.com/@babel/standalone@7.29.0/babel.min.js"

بعدها البرنامج يعمل بلا أي اتصال خارجي.
