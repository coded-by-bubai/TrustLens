// TrustLens Background Service Worker (Manifest V3)

chrome.runtime.onInstalled.addListener(() => {
  // Create Context Menus
  chrome.contextMenus.create({
    id: 'trustlens-inspect-link',
    title: 'Inspect Link with TrustLens',
    contexts: ['link']
  });

  chrome.contextMenus.create({
    id: 'trustlens-analyze-selection',
    title: 'Analyze Selected Text for Scams',
    contexts: ['selection']
  });
});

// Handle Context Menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'trustlens-inspect-link' && info.linkUrl) {
    try {
      const response = await fetch('http://127.0.0.1:8000/api/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: info.linkUrl })
      });
      const data = await response.json();
      
      const badgeText = data.overall_risk === 'Confirmed Malicious' ? 'CRIT' :
                        data.overall_risk === 'High Risk' ? 'HIGH' :
                        data.overall_risk === 'Suspicious' ? 'SUSP' : 'SAFE';
      
      const badgeColor = data.overall_risk === 'Confirmed Malicious' || data.overall_risk === 'High Risk' ? '#ef4444' :
                         data.overall_risk === 'Suspicious' ? '#f59e0b' : '#10b981';

      if (tab && tab.id) {
        chrome.action.setBadgeText({ tabId: tab.id, text: badgeText });
        chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: badgeColor });
      }
    } catch (e) {
      console.error('TrustLens background inspection error:', e);
    }
  } else if (info.menuItemId === 'trustlens-analyze-selection' && info.selectionText) {
    try {
      await chrome.storage.local.set({ pendingScamText: info.selectionText });
      chrome.action.openPopup?.();
    } catch (e) {
      console.error('Error opening popup:', e);
    }
  }
});

// Message listener for tab updates and communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateBadge' && sender.tab) {
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: request.text });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: request.color });
    sendResponse({ success: true });
  }
  return true;
});

