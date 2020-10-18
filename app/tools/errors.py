class DNSError(Exception):
    """Raised when the resolv cannot be done"""
    pass


class TimeExceeded(Exception):
    """Raised when the packet cannot reach the destination"""
    pass


class UnknownError(Exception):
    """Raised when the error is unknown (not implemented yet)"""
    pass
