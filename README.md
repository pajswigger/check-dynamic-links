# Check Dynamic Links

This is a Burp extension that helps detect vulnerabilities in scenarios that Burp would otherwise miss:

 * Cross domain script include
 * Cross domain referer leakage

The core Burp check works by parsing the HTML page and identifying vulnerable script tags or links. However, this cannot identify links that are dynamically created by JavaScript.

This extension works by looking at the Referer header on all requests. If a request is seen with a JavaScript content type, and a referer from a different domain, this is CDSI.
If a request has a referer that includes a query string and is from a different domain, that is CDRL.
