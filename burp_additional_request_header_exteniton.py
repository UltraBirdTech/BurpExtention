from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpXtender, IHttpListner):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Homemade Extension")
        callbacks.registerHttpListener(self)
        return
