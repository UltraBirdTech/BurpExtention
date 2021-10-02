from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpXtender, IHttpListner):
    def registerExtenderCallbacks(self, callbacks):
        pass
