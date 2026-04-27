const WALLET_URL = chrome.runtime.getURL("wallet.html");

chrome.action.onClicked.addListener(async () => {
  await chrome.tabs.create({ url: WALLET_URL });
});
