// ic-git verifier -- page (main world) script, at document_start on /site/
// pages and on every page of a domain the core pins. Runs before the
// page's own markup is parsed.
//
// document.open() here aborts the delivered response: its parser is
// dropped, so none of the page the network delivered is parsed or run. (Not
// window.stop(): that marks the parser aborted, and document.open() is then
// a no-op.) What the tab shows is written next, once, by the isolated
// content script -- the checked bytes, or a bare document for the stop
// page. The document keeps its origin and the Content-Security-Policy of
// the response, so the pinned policy applies to what is written.
(() => {
  // Only an HTML document can be opened: on any other (a response typed as
  // XML, XHTML or SVG) document.open() throws, and the delivered page would
  // be parsed and shown. rules.json types every page under /site/ (and at a
  // pinned domain) as text/html, so this is that rule not holding -- or
  // open() failing in some other way: throwing, or doing nothing, which
  // leaves the document its nodes where an open one has none. Then stop
  // the load, empty what was parsed, and take no write, so the content
  // script finds its write refused and shows the stop page instead.
  const opened = document.contentType === 'text/html' && (() => {
    try { document.open(); } catch (_) { return false; }
    return document.firstChild === null;
  })();
  if (!opened) {
    window.stop();
    document.replaceChildren();
    return;
  }
  // After open(), which erases the document's listeners. The write is
  // acknowledged by cancelling the event, once it is done: the content
  // script reports the page shown only then.
  document.addEventListener('ic-git-verifier:write', e => {
    document.write(String(e.detail));
    document.close();
    e.preventDefault();
  }, { once: true });
  // Whether a service worker answered for this page and answers its
  // requests, as the page's world sees it: said to the content script by
  // cancelling its event.
  document.addEventListener('ic-git-verifier:controlled', e => {
    if (navigator.serviceWorker && navigator.serviceWorker.controller) e.preventDefault();
  });
})();
