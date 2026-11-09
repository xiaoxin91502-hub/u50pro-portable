// U50 Pro 控制台 v1.7.0 随身版 — 注入加载器（由 build-portable.js 生成，勿手改）。
// 由 bookmarklet 在原厂页面（http://192.168.0.1）里加载。只做四件事：
//   1. 检查当前页是不是路由器页面（不是就提示，不乱注入）；
//   2. 设直连标志 window.__U50PRO_DIRECT__ = true；
//   3. 从自己的 <script src> 推导托管地址，加载同目录的 console-data.js；
//   4. 把页面文档里的构建时 HOST 换成真实托管地址，document.write 写进当前页。
// 密码、LD、cookie 只在浏览器内存里流转，本文件不保存任何东西。
(function () {
  if (window.__U50PRO_CONSOLE_DOC__) return; // 已注入过，不重复跑
  var host = location.hostname || '';
  var isPrivateIp = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(host) || host === 'localhost';
  if (!isPrivateIp) {
    alert('请先打开 U50 原厂页面 http://192.168.0.1，再点收藏夹里的“U50 控制台”。');
    return;
  }
  window.__U50PRO_DIRECT__ = true;
  // 从自己的 script 地址推导托管目录（不用构建时 HOST，换托管不用重建）。
  var mySrc = '';
  try { mySrc = (document.currentScript && document.currentScript.src) || ''; } catch (e) {}
  if (!mySrc) {
    var scripts = document.getElementsByTagName('script');
    for (var i = scripts.length - 1; i >= 0; i--) {
      if ((scripts[i].src || '').indexOf('loader.js') !== -1) { mySrc = scripts[i].src; break; }
    }
  }
  var base = mySrc ? mySrc.replace(/\/loader\.js(\?.*)?$/, '') : 'https://HOST/u50pro-portable';
  var s = document.createElement('script');
  s.src = base + '/console-data.js';
  s.onload = function () {
    var doc = window.__U50PRO_CONSOLE_DOC__ || '';
    // 把构建时 HOST 换成真实托管地址（两者相同时无变化）。
    if (base !== 'https://HOST/u50pro-portable') doc = doc.split('https://HOST/u50pro-portable').join(base);
    document.open();
    document.write(doc);
    document.close();
  };
  s.onerror = function () {
    alert('随身版加载失败：打不开 ' + base + '/console-data.js。请检查手机是否连着 U50 的 Wi-Fi、托管地址是否还能访问。');
  };
  (document.head || document.documentElement).appendChild(s);
})();
