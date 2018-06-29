package burp

import java.net.URL


class BurpExtender : IBurpExtender {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Companion.callbacks = callbacks
        callbacks.setExtensionName("Check Dynamic Links")
        callbacks.registerScannerCheck(CrossDomainScriptIncludeCheck(callbacks))
        callbacks.registerScannerCheck(CrossDomainRefererLeakageCheck(callbacks))
    }
}


interface PassiveCheck : IScannerCheck {
    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue): Int {
        return 0
    }

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse, insertionPoint: IScannerInsertionPoint): List<IScanIssue> {
        return emptyList()
    }
}


interface MyIssue : IScanIssue {
    override val httpService: IHttpService
        get() = BurpExtender.callbacks.helpers.buildHttpService(url.host, if (url.port == -1) { url.defaultPort } else { url.port }, url.protocol)
    override val confidence: String
        get() = "Certain"
    override val severity: String
        get() = "Information"
    override val issueType: Int
        get() = 0
    override val issueDetail: String?
        get() = null
    override val remediationDetail: String?
        get() = null
}


class CrossDomainScriptIncludeCheck(val callbacks: IBurpExtenderCallbacks) : PassiveCheck {
    private val javaScriptContentTypes = setOf("text/javascript", "application/javascript")

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse): List<IScanIssue> {
        val responseInfo = callbacks.helpers.analyzeResponse(baseRequestResponse.response!!)
        val contentType = getHeader("Content-type", responseInfo.headers)

        val requestInfo = callbacks.helpers.analyzeRequest(baseRequestResponse.request)
        val refererString = getHeader("Referer", requestInfo.headers) ?: return emptyList()
        val referer = URL(refererString)

        if(javaScriptContentTypes.contains(contentType) && baseRequestResponse.httpService.host != referer.host) {
            callbacks.addScanIssue(CrossDomainScriptIncludeIssue(referer, arrayOf(highlightString(baseRequestResponse, refererString))))
        }
        return emptyList()
    }
}


class CrossDomainScriptIncludeIssue(
        override val url: URL,
        override val httpMessages: Array<IHttpRequestResponse>) : MyIssue {
    override val issueName: String
        get() = "Cross domain script include (dynamic)"
    override val issueBackground: String?
        get() = "The application includes a script from a third-party domain, which allows that domain to take control of the application."
    override val remediationBackground: String?
        get() = "Host scripts on the application domain."
}


class CrossDomainRefererLeakageCheck(val callbacks: IBurpExtenderCallbacks) : PassiveCheck {
    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse): List<IScanIssue> {
        val requestInfo = callbacks.helpers.analyzeRequest(baseRequestResponse.request)
        val refererString = getHeader("Referer", requestInfo.headers) ?: return emptyList()
        val referer = URL(refererString)

        if(baseRequestResponse.httpService.host != referer.host) {
            callbacks.addScanIssue(CrossDomainRefererLeakageIssue(referer, arrayOf(highlightString(baseRequestResponse, refererString))))
        }
        return emptyList()
    }
}


class CrossDomainRefererLeakageIssue(
        override val url: URL,
        override val httpMessages: Array<IHttpRequestResponse>) : MyIssue {
    override val issueName: String
        get() = "Cross domain referer leakage (dynamic)"
    override val issueBackground: String?
        get() = "The application leaks confidential URLs to third-party domains through the Referer header."
    override val remediationBackground: String?
        get() = "User the rel=\"noreferrer\" option on links to third-party domains."
}


fun getHeader(header: String, headers: List<String>): String? {
    val headerColon = "$header: "
    for(hdr in headers) {
        if(hdr.startsWith(headerColon, ignoreCase = true)) {
            return hdr.substring(headerColon.length).trim()
        }
    }
    return null
}


fun highlightString(message: IHttpRequestResponse, highlight: String): IHttpRequestResponseWithMarkers {
    val highlightPos = BurpExtender.callbacks.helpers.indexOf(message.request, highlight.toByteArray(Charsets.ISO_8859_1), true, 0, message.request.size)
    return BurpExtender.callbacks.applyMarkers(message, listOf(intArrayOf(highlightPos, highlightPos + highlight.length)), emptyList())
}
