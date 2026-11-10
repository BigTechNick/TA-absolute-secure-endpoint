class RESTException(Exception):
    def __init__(self, statusCode, msg=""):
        super().__init__(msg)
        self.statusCode = statusCode
        self.msg = msg
