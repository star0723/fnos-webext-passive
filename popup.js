(() => {
  const api = (typeof browser !== 'undefined') ? browser : chrome;
  const VULN_BASE = "/app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../";

  const elOrigin = document.getElementById('origin');
  const elResultCard = document.getElementById('resultCard');
  const elResultIcon = document.getElementById('resultIcon');
  const elResultStatus = document.getElementById('resultStatus');
  const elResultMeta = document.getElementById('resultMeta');
  const elFileListContainer = document.getElementById('fileListContainer');
  const elPreviewBox = document.getElementById('previewBox');
  const elDownloadBar = document.getElementById('downloadBar');
  const elSelectAll = document.getElementById('selectAll');
  const elSelectedCount = document.getElementById('selectedCount');
  const elDownloadProgress = document.getElementById('downloadProgress');
  const elProgressText = document.getElementById('progressText');
  const elProgressFill = document.getElementById('progressFill');
  const btnScan = document.getElementById('btnScan');
  const btnRefresh = document.getElementById('btnRefresh');
  const btnCopy = document.getElementById('btnCopy');
  const btnClear = document.getElementById('btnClear');
  const btnDownload = document.getElementById('btnDownload');
  const btnDownloadZip = document.getElementById('btnDownloadZip');

  let currentOrigin = null;
  let currentTabId = null;
  let currentResult = null;
  let currentSubPath = '';
  let selectedFiles = new Map(); // url -> {filename, url}
  let allFileLinks = [];
  let isDownloading = false;

  function extractFileName(href) {
    if (!href) return null;
    const vulnMatch = href.match(/[?&]size=(?:\.\.\/){4}.*?([^\/]+\/?)$/);
    if (vulnMatch) return vulnMatch[1];
    if (/^(https?:)?\/\//i.test(href)) return null;
    if (/^(#|javascript:|mailto:|data:)/i.test(href)) return null;
    if (href.startsWith('/')) return null;
    if (href.includes('://')) return null;
    if (href === '../' || href === '..') return null;
    return href.trim();
  }

  function parseLinks(html) {
    const links = [];
    const regex = /<a\s+href="([^"]+)"[^>]*>([^<]*)<\/a>/gi;
    let match;
    while ((match = regex.exec(html)) !== null) {
      const rawHref = match[1];
      const name = (match[2] || '').trim();
      const fileName = extractFileName(rawHref);
      if (!fileName) continue;
      if (!/^[^\/\?#]+\/?$/.test(fileName)) continue;
      links.push({ name: name || fileName, href: fileName, isDir: fileName.endsWith('/') });
    }
    return links;
  }

  function getFileIcon(name, isDir) {
    if (isDir) return '📁';
    const ext = name.split('.').pop().toLowerCase();
    const icons = {
      'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'bmp': '🖼️', 'webp': '🖼️', 'svg': '🖼️',
      'mp4': '🎬', 'mkv': '🎬', 'avi': '🎬', 'mov': '🎬',
      'mp3': '🎵', 'wav': '🎵', 'flac': '🎵',
      'pdf': '📕', 'doc': '📘', 'docx': '📘', 'xls': '📗', 'xlsx': '📗',
      'txt': '📄', 'md': '📝', 'json': '📋', 'xml': '📋',
      'js': '💛', 'py': '🐍', 'java': '☕', 'html': '🌐', 'css': '🎨',
      'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'gz': '📦',
      'exe': '⚙️', 'sh': '🔧',
      'conf': '⚙️', 'yml': '⚙️', 'yaml': '⚙️',
      'db': '🗃️', 'sql': '🗃️',
      'log': '📜', 'bak': '💾'
    };
    return icons[ext] || '📄';
  }

  function buildVulnUrl(origin, subPath) {
    const cleanPath = (subPath || '').replace(/^\/+/, '');
    return origin + VULN_BASE + cleanPath;
  }

  function createMetaTag(text, highlight = false) {
    const tag = document.createElement('span');
    tag.className = 'meta-tag' + (highlight ? ' highlight' : '');
    tag.textContent = text;
    return tag;
  }

  // 更新选中计数和按钮状态
  function updateSelectedCount() {
    const count = selectedFiles.size;
    elSelectedCount.textContent = `已选 ${count} 个文件`;
    btnDownload.disabled = count === 0 || isDownloading;
    btnDownloadZip.disabled = count === 0 || isDownloading;
    
    const allFiles = allFileLinks.filter(l => !l.isDir);
    if (allFiles.length === 0) {
      elSelectAll.checked = false;
      elSelectAll.indeterminate = false;
    } else if (count === allFiles.length) {
      elSelectAll.checked = true;
      elSelectAll.indeterminate = false;
    } else if (count > 0) {
      elSelectAll.checked = false;
      elSelectAll.indeterminate = true;
    } else {
      elSelectAll.checked = false;
      elSelectAll.indeterminate = false;
    }
  }

  // 同步所有复选框的视觉状态
  function syncCheckboxUI() {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    checkboxes.forEach(cb => {
      const url = cb.dataset.url;
      const isSelected = selectedFiles.has(url);
      cb.checked = isSelected;
      const item = cb.closest('.file-item');
      if (item) {
        if (isSelected) {
          item.classList.add('selected');
        } else {
          item.classList.remove('selected');
        }
      }
    });
  }

  function showProgress(show) {
    elDownloadProgress.style.display = show ? 'block' : 'none';
  }

  function updateProgress(text, percent) {
    elProgressText.textContent = text;
    elProgressFill.style.width = percent + '%';
  }

  // 让出主线程，避免卡顿
  function yieldToMain() {
    return new Promise(resolve => setTimeout(resolve, 0));
  }

  function createFileItem(link, basePath, origin) {
    const item = document.createElement('div');
    item.className = 'file-item' + (link.isDir ? ' dir' : '');
    
    const fileName = link.href.replace(/^\/+/, '');
    const fullPath = basePath + fileName;
    const fullUrl = buildVulnUrl(origin, fullPath);

    // 文件显示复选框
    if (!link.isDir) {
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'file-checkbox';
      checkbox.dataset.url = fullUrl;
      checkbox.dataset.filename = link.name;
      checkbox.checked = selectedFiles.has(fullUrl);
      
      checkbox.addEventListener('change', (e) => {
        e.stopPropagation();
        if (checkbox.checked) {
          selectedFiles.set(fullUrl, { filename: link.name, url: fullUrl });
          item.classList.add('selected');
        } else {
          selectedFiles.delete(fullUrl);
          item.classList.remove('selected');
        }
        updateSelectedCount();
      });
      
      checkbox.addEventListener('click', (e) => e.stopPropagation());
      item.appendChild(checkbox);
      
      if (selectedFiles.has(fullUrl)) {
        item.classList.add('selected');
      }
    }

    const icon = document.createElement('span');
    icon.className = 'file-icon';
    icon.textContent = getFileIcon(link.name, link.isDir);

    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = link.name;

    const arrow = document.createElement('span');
    arrow.className = 'file-arrow';
    arrow.textContent = link.isDir ? '📂' : '↗';

    item.appendChild(icon);
    item.appendChild(name);
    item.appendChild(arrow);
    item.title = '/' + fullPath;

    item.addEventListener('click', (e) => {
      if (isDownloading) return;
      if (link.isDir) {
        window.open(fullUrl, '_blank');
      } else {
        const checkbox = item.querySelector('.file-checkbox');
        if (checkbox && e.target !== checkbox) {
          checkbox.checked = !checkbox.checked;
          checkbox.dispatchEvent(new Event('change'));
        }
      }
    });

    return item;
  }

  function render(result) {
    currentResult = result;
    selectedFiles.clear();
    allFileLinks = [];
    elResultMeta.innerHTML = '';
    elFileListContainer.innerHTML = '';
    elPreviewBox.style.display = 'none';
    elDownloadBar.style.display = 'none';
    showProgress(false);
    elSelectAll.checked = false;
    elSelectAll.indeterminate = false;

    if (!result) {
      elResultCard.className = 'result-card unknown';
      elResultIcon.textContent = '⏳';
      elResultStatus.textContent = '等待检测...';
      return;
    }

    if (result.vulnerable) {
      elResultCard.className = 'result-card vuln';
      elResultIcon.textContent = '⚠️';
      elResultStatus.textContent = result.isListing ? '目录浏览中' : '发现漏洞！';
    } else if (result.probed && !result.error) {
      elResultCard.className = 'result-card safe';
      elResultIcon.textContent = '✅';
      elResultStatus.textContent = '安全';
    } else if (result.error) {
      elResultCard.className = 'result-card unknown';
      elResultIcon.textContent = '❓';
      elResultStatus.textContent = '检测异常';
    } else {
      elResultCard.className = 'result-card unknown';
      elResultIcon.textContent = '⏳';
      elResultStatus.textContent = '检测中...';
    }

    if (result.time) elResultMeta.appendChild(createMetaTag('🕐 ' + new Date(result.time).toLocaleString()));
    if (result.status) elResultMeta.appendChild(createMetaTag('HTTP ' + result.status, result.status === 200));
    if (result.length !== undefined) elResultMeta.appendChild(createMetaTag(result.length + ' bytes'));
    if (result.fingerprint) elResultMeta.appendChild(createMetaTag('🔍 自动', true));
    if (result.manual) elResultMeta.appendChild(createMetaTag('👆 手动'));
    if (result.isListing) elResultMeta.appendChild(createMetaTag('📂 目录', true));
    if (result.error) elResultMeta.appendChild(createMetaTag('⚠️ ' + result.error));

    currentSubPath = (result.subPath || '').replace(/^\/+/, '');
    let basePath = currentSubPath;
    if (basePath && !basePath.endsWith('/')) basePath += '/';

    if (result.vulnerable) {
      let links = result.links || [];
      if (links.length === 0 && result.preview) {
        links = parseLinks(result.preview);
      }
      allFileLinks = links;

      // 面包屑
      const pathDiv = document.createElement('div');
      pathDiv.className = 'current-path';
      let breadcrumb = '<span class="path-label">📍</span>';
      breadcrumb += `<a href="${buildVulnUrl(currentOrigin, '')}" target="_blank" class="crumb">/</a>`;
      
      if (currentSubPath) {
        const parts = currentSubPath.split('/').filter(p => p);
        let accumulated = '';
        parts.forEach(part => {
          accumulated += part + '/';
          breadcrumb += `<a href="${buildVulnUrl(currentOrigin, accumulated)}" target="_blank" class="crumb">${part}</a>/`;
        });
      }
      pathDiv.innerHTML = breadcrumb;
      elFileListContainer.appendChild(pathDiv);

      if (links.length > 0) {
        const dirs = links.filter(l => l.isDir).length;
        const files = links.length - dirs;

        const titleDiv = document.createElement('div');
        titleDiv.className = 'file-list-title';
        titleDiv.textContent = `📂 ${dirs} 文件夹, 📄 ${files} 文件`;
        elFileListContainer.appendChild(titleDiv);

        const listDiv = document.createElement('div');
        listDiv.className = 'file-list';
        
        const sorted = [...links].sort((a, b) => {
          if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        
        sorted.forEach(link => {
          listDiv.appendChild(createFileItem(link, basePath, currentOrigin));
        });
        elFileListContainer.appendChild(listDiv);

        if (files > 0) {
          elDownloadBar.style.display = 'flex';
          updateSelectedCount();
        }
      } else if (result.preview) {
        const noFileDiv = document.createElement('div');
        noFileDiv.className = 'empty-hint';
        noFileDiv.textContent = '未解析到文件链接';
        elFileListContainer.appendChild(noFileDiv);
        elPreviewBox.style.display = 'block';
        elPreviewBox.textContent = result.preview;
      }
    } else if (result.preview) {
      elPreviewBox.style.display = 'block';
      elPreviewBox.textContent = result.preview;
    }
  }

  // ✅ 修复：全选功能 - 直接操作 selectedFiles，然后同步 UI
  elSelectAll.addEventListener('change', () => {
    const shouldSelect = elSelectAll.checked;
    const basePath = currentSubPath + (currentSubPath && !currentSubPath.endsWith('/') ? '/' : '');
    
    // 获取所有文件（非目录）
    const allFiles = allFileLinks.filter(l => !l.isDir);
    
    if (shouldSelect) {
      // 全选：添加所有文件到 selectedFiles
      allFiles.forEach(link => {
        const fileName = link.href.replace(/^\/+/, '');
        const fullPath = basePath + fileName;
        const fullUrl = buildVulnUrl(currentOrigin, fullPath);
        selectedFiles.set(fullUrl, { filename: link.name, url: fullUrl });
      });
    } else {
      // 取消全选：清空 selectedFiles
      selectedFiles.clear();
    }
    
    // 同步复选框 UI
    syncCheckboxUI();
    updateSelectedCount();
  });

  // ✅ 修复：打包下载 - 添加分批处理和错误恢复
  btnDownloadZip.addEventListener('click', async () => {
    if (selectedFiles.size === 0 || isDownloading) return;
    
    isDownloading = true;
    btnDownloadZip.disabled = true;
    btnDownload.disabled = true;
    elSelectAll.disabled = true;
    btnDownloadZip.innerHTML = '<span>⏳</span> 打包中';
    showProgress(true);
    
    const files = Array.from(selectedFiles.values());
    const zip = new JSZip();
    let completed = 0;
    let failed = 0;
    const failedFiles = [];
    
    // 分批处理，每批 3 个文件
    const batchSize = 3;
    
    for (let i = 0; i < files.length; i += batchSize) {
      const batch = files.slice(i, i + batchSize);
      
      // 并行获取一批文件
      const results = await Promise.allSettled(
        batch.map(async (file) => {
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30秒超时
            
            const resp = await fetch(file.url, { 
              credentials: 'include',
              signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (resp.ok) {
              const blob = await resp.blob();
              return { success: true, filename: file.filename, blob };
            } else {
              return { success: false, filename: file.filename, error: `HTTP ${resp.status}` };
            }
          } catch (e) {
            return { success: false, filename: file.filename, error: e.message };
          }
        })
      );
      
      // 处理结果
      for (const result of results) {
        if (result.status === 'fulfilled' && result.value.success) {
          zip.file(result.value.filename, result.value.blob);
          completed++;
        } else {
          failed++;
          const errorInfo = result.status === 'fulfilled' 
            ? result.value 
            : { filename: 'unknown', error: result.reason };
          failedFiles.push(errorInfo.filename);
        }
      }
      
      const progress = Math.round(((completed + failed) / files.length) * 80);
      updateProgress(`获取文件 ${completed + failed}/${files.length}${failed > 0 ? ` (${failed} 失败)` : ''}`, progress);
      
      // 让出主线程
      await yieldToMain();
    }

    if (completed > 0) {
      updateProgress('生成 ZIP 文件...', 85);
      await yieldToMain();
      
      try {
        const zipBlob = await zip.generateAsync({ 
          type: 'blob',
          compression: 'DEFLATE',
          compressionOptions: { level: 6 }
        }, (metadata) => {
          // 更新压缩进度
          const zipProgress = 85 + Math.round(metadata.percent * 0.15);
          updateProgress(`压缩中 ${Math.round(metadata.percent)}%`, zipProgress);
        });
        
        // 生成文件名
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const dirName = currentSubPath ? currentSubPath.split('/').filter(p => p).pop() || 'files' : 'root';
        const zipFilename = `fnos_${dirName}_${timestamp}.zip`;
        
        // 下载
        const url = URL.createObjectURL(zipBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = zipFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        // 延迟释放 URL
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        
        let msg = `完成！${completed} 个文件已打包`;
        if (failed > 0) {
          msg += `，${failed} 个失败`;
        }
        updateProgress(msg, 100);
      } catch (e) {
        console.error('ZIP generation failed:', e);
        updateProgress('ZIP 生成失败: ' + e.message, 100);
      }
    } else {
      updateProgress(`所有文件获取失败`, 100);
    }
    
    setTimeout(() => {
      showProgress(false);
      isDownloading = false;
      elSelectAll.disabled = false;
      btnDownloadZip.innerHTML = '<span>📦</span> ZIP';
      updateSelectedCount();
    }, 3000);
  });

  // 逐个下载
  btnDownload.addEventListener('click', async () => {
    if (selectedFiles.size === 0 || isDownloading) return;
    
    isDownloading = true;
    btnDownload.disabled = true;
    btnDownloadZip.disabled = true;
    elSelectAll.disabled = true;
    btnDownload.innerHTML = '<span>⏳</span>';
    showProgress(true);
    
    const files = Array.from(selectedFiles.values());
    let completed = 0;
    let failed = 0;

    for (const file of files) {
      try {
        updateProgress(`下载 ${completed + failed + 1}/${files.length}: ${file.filename}`, Math.round(((completed + failed) / files.length) * 100));
        
        await api.runtime.sendMessage({
          type: 'FNOS_DOWNLOAD_FILE',
          url: file.url,
          filename: file.filename
        });
        
        completed++;
      } catch (e) {
        console.error('Download failed:', file.url, e);
        failed++;
      }
      
      // 每个文件间隔 300ms，避免下载过快
      await new Promise(r => setTimeout(r, 300));
    }
    
    let msg = `完成！${completed} 个文件`;
    if (failed > 0) msg += `，${failed} 个失败`;
    updateProgress(msg, 100);
    
    setTimeout(() => {
      showProgress(false);
      isDownloading = false;
      elSelectAll.disabled = false;
      btnDownload.innerHTML = '<span>⬇️</span>';
      updateSelectedCount();
    }, 2000);
  });

  async function getTab() {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    const tab = tabs?.[0];
    if (!tab?.url) return { origin: null, tabId: null };
    try {
      return { origin: new URL(tab.url).origin, tabId: tab.id };
    } catch {
      return { origin: null, tabId: null };
    }
  }

  async function refresh() {
    const { origin, tabId } = await getTab();
    currentOrigin = origin;
    currentTabId = tabId;
    elOrigin.textContent = currentOrigin || '无法获取';

    if (!currentOrigin || /^(chrome|moz|about|edge)/.test(currentOrigin)) {
      render(null);
      return;
    }

    await api.runtime.sendMessage({ type: 'FNOS_REFRESH_TAB', tabId: currentTabId }).catch(() => {});
    await new Promise(r => setTimeout(r, 500));
    const resp = await api.runtime.sendMessage({ type: 'FNOS_GET_RESULT', origin: currentOrigin }).catch(() => null);
    render(resp?.result);
  }

  btnScan.addEventListener('click', async () => {
    if (!currentOrigin || !currentTabId) return;
    btnScan.innerHTML = '<span>⏳</span> 扫描中';
    btnScan.disabled = true;
    const resp = await api.runtime.sendMessage({ type: 'FNOS_MANUAL_SCAN', origin: currentOrigin, tabId: currentTabId }).catch(e => ({ error: e.message }));
    render(resp?.result || { probed: true, error: resp?.error || 'FAILED' });
    btnScan.innerHTML = '<span>🔍</span> 扫描';
    btnScan.disabled = false;
  });

  btnRefresh.addEventListener('click', async () => {
    btnRefresh.disabled = true;
    await refresh();
    btnRefresh.disabled = false;
  });

  btnCopy.addEventListener('click', async () => {
    const report = { 
      tool: 'fnOS-CVE-Scanner', 
      version: '1.5.1',
      target: currentOrigin, 
      vulnerable: currentResult?.vulnerable, 
      path: currentResult?.subPath, 
      result: currentResult, 
      time: new Date().toISOString() 
    };
    await navigator.clipboard.writeText(JSON.stringify(report, null, 2)).catch(() => {});
    btnCopy.innerHTML = '<span>✅</span>';
    setTimeout(() => btnCopy.innerHTML = '<span>📋</span>', 800);
  });

  btnClear.addEventListener('click', async () => {
    await api.runtime.sendMessage({ type: 'FNOS_CLEAR' }).catch(() => {});
    await refresh();
  });

  refresh();
})();
