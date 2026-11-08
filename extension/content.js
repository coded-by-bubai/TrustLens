// TrustLens Content Script - In-Page Link & DOM Threat Inspector

(() => {
  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageStats') {
      const links = Array.from(document.querySelectorAll('a[href]'));
      const currentHost = window.location.hostname;
      
      let insecureHttpLinks = 0;
      let externalLinks = 0;
      let passwordFormsInsecure = false;

      links.forEach((a) => {
        try {
          const url = new URL(a.href, window.location.href);
          if (url.protocol === 'http:') {
            insecureHttpLinks++;
          }
          if (url.hostname && url.hostname !== currentHost) {
            externalLinks++;
          }
        } catch (e) {
          // ignore invalid URLs
        }
      });

      // Check for password inputs on non-HTTPS page
      if (window.location.protocol === 'http:') {
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        if (passwordInputs.length > 0) {
          passwordFormsInsecure = true;
        }
      }

      sendResponse({
        totalLinks: links.length,
        insecureHttpLinks: insecureHttpLinks,
        externalLinks: externalLinks,
        passwordFormsInsecure: passwordFormsInsecure,
        pageTitle: document.title,
        isHttps: window.location.protocol === 'https:'
      });
    }
    return true;
  });
})();

