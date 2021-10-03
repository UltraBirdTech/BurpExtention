from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def __init__(self):
        self.new_header = "X-Original-Header: UltraBird"
    
    # DOC: [Method] https://portswigger.net/Burp/extender/api/burp/IBurpExtender.html#registerExtenderCallbacks(burp.IBurpExtenderCallbacks)
    # DOC: [Verb]   https://portswigger.net/Burp/extender/api/burp/IBurpExtenderCallbacks.html
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("My Original Extension")
        callbacks.registerHttpListener(self)
        return

    def processHttpMessage(self, tool_flag, is_message_request, current_request):
        if not is_message_request:
            return

        request_info = self.get_request_info(current_request)

        header_list = self.get_header_from_request_info(request_info)
        body_info = self.get_body_from_request_info(current_request, request_info)

        new_request = self.create_new_request(header_list, body_info)
        current_request.setRequest(new_request)

        return

    def get_request_info(self, current_request):
        return self._helpers.analyzeRequest(current_request)

    def get_header_from_request_info(self, request_info):
        return list(request_info.getHeaders())

    def get_body_from_request_info(self, current_request, request_info):
        body_bytes = current_request.getRequest()[request_info.getBodyOffset():]
        return self._helpers.bytesToString(body_bytes)

    def create_new_request(self, header_list, body_info):
        header_list.append(self.new_header)
        return self._helpers.buildHttpMessage(header_list, body_info)
