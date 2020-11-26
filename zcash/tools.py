def concat(val:int, source:bytes) -> bytes:
    """

    """
    source = int(str(source), 16)
    if val == 1:
        return source >> 1 | 1 << 255
    elif val == 2:
        return source >> 2 | 1 << 255
    return source
