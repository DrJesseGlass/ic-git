// ic-git verifier -- page (main world) script, at document_start on /site/
// pages. Runs before the page's own markup is parsed.
//
// document.open() here aborts the delivered response: its parser is
// dropped, so none of the page the network delivered is parsed or run. (Not
// window.stop(): that marks the parser aborted, and document.open() is then
// a no-op.) What the tab shows is written next, once, by the isolated
// content script -- the checked bytes, or a bare document for the stop
// page. The document keeps its origin and the Content-Security-Policy of
// the response, so the pinned policy applies to what is written.
(() => {
  document.open();
  // After open(), which erases the document's listeners.
  document.addEventListener('ic-git-verifier:write', e => {
    document.write(String(e.detail));
    document.close();
  }, { once: true });
})();
