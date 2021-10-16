
def number2string(i):
    """Convert a number to a string

    Input: long or integer
    Output: string (big-endian)
    """
    return i.to_bytes((7 + i.bit_length()) // 8, 'big')


def number2string_N(i, n):
    """Convert a number to a string of fixed size

    i: long or integer
    N: length of string
    Output: string (big-endian)
    """
    number2string(i)
    return i.to_bytes(n, 'big')


def string2number(i):
    """Convert a string to a number

    Input: string (big-endian)
    Output: long or integer
    """
    return int.from_bytes(i, 'big')


def xorstring(a, b):
    """XOR two strings of same length

    For more complex cases, see CryptoPlus.Cipher.XOR"""
    assert len(a) == len(b)
    return number2string_N(string2number(a) ^ string2number(b), len(a))


class Counter(str):
    # found here: http://www.lag.net/pipermail/paramiko/2008-February.txt
    """Necessary for CTR chaining mode

    Initializing a counter object (ctr = Counter('xxx'), gives a value to the
    counter object.
    Every time the object is called ( ctr() ) it returns the current value and
    increments it by 1.
    Input/output is a raw string, counter value is big-endian.
    """

    def __init__(self, initial_ctr):
        if not isinstance(initial_ctr, bytes):
            raise TypeError("nonce must be bytes")
        self.c = string2number(initial_ctr)

    def __call__(self):
        # This might be slow, but it works as a demonstration
        ctr = number2string_N(self.c, 16)
        self.c += 1
        return ctr
