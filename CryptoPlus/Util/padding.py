# =============================================================================
# Copyright (c) 2008 Christophe Oosterlynck <christophe.oosterlynck_AT_gmail.com>
#                    & NXP ( Philippe Teuwen <philippe.teuwen_AT_nxp.com> )
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# =============================================================================

"""Module for padding functions

padding info here: https://en.wikipedia.org/wiki/Padding_(cryptography)
"""

import random

PAD = 0
UNPAD = 1


def bit_padding(pad_data, direction, length=None):
    """Pad a string using bitPadding

        padData = raw string to pad/unpad
        direction = PAD or UNPAD
        length = amount of bytes the padded string should be a multiple of
                 (length variable is not used when unpadding)

        returns: (un)padded raw string

        A new block full of padding will be added when padding data that is
        already a multiple of the length.

        Example:
        =========
        >>> from CryptoPlus.Util import padding

        >>> padding.bit_padding(b'test', padding.PAD, 8)
        b'test\\x80\\x00\\x00\\x00'
        >>> padding.bit_padding(_, padding.UNPAD)
        b'test'
    """
    if direction == PAD:
        if length is None:
            raise ValueError("Supply a valid length")
        return __bit_padding(pad_data, length)
    elif direction == UNPAD:
        return __bit_padding_unpad(pad_data)
    else:
        raise ValueError("Supply a valid direction")


def __bit_padding(to_pad, length):
    padded = to_pad + b'\x80' + b'\x00' * (length - len(to_pad) % length - 1)
    return padded


def __bit_padding_unpad(padded):
    if padded.rstrip(b'\x00')[-1:] == b'\x80':
        return padded.rstrip(b'\x00')[:-1]
    else:
        return padded


def zeros_padding(pad_data, direction, length=None):
    """Pad a string using zerosPadding

        padData = raw string to pad/unpad
        direction = PAD or UNPAD
                    beware: padding and unpadding a string ending in 0's
                            will remove those 0's too
        length = amount of bytes the padded string should be a multiple of
                 (length variable is not used when unpadding)

        returns: (un)padded raw string

        No padding will be added when padding data that is already a
        multiple of the given length.

        Example:
        =========
        >>> from CryptoPlus.Util import padding

        >>> padding.zeros_padding(b'12345678', padding.PAD, 16)
        b'12345678\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        >>> padding.zeros_padding(_, padding.UNPAD)
        b'12345678'
    """
    if direction == PAD:
        if length is None:
            raise ValueError("Supply a valid length")
        return __zeros_padding(pad_data, length)
    elif direction == UNPAD:
        return __zeros_padding_unpad(pad_data)
    else:
        raise ValueError("Supply a valid direction")


def __zeros_padding(toPad, length):
    pad_length = (length - len(toPad)) % length
    return toPad + b'\x00' * pad_length


def __zeros_padding_unpad(padded):
    return padded.rstrip(b'\x00')


def PKCS7(pad_data, direction, length=None):
    """Pad a string using PKCS7

        padData = raw string to pad/unpad
        direction = PAD or UNPAD
        length = amount of bytes the padded string should be a multiple of
                 (length variable is not used when unpadding)

        returns: (un)padded raw string

        A new block full of padding will be added when padding data that is
        already a multiple of the given length.

        Example:
        =========
        >>> from CryptoPlus.Util import padding

        >>> padding.PKCS7(b'12345678', padding.PAD, 16)
        b'12345678\\x08\\x08\\x08\\x08\\x08\\x08\\x08\\x08'
        >>> padding.PKCS7(_, padding.UNPAD)
        b'12345678'
    """
    if direction == PAD:
        if length is None:
            raise ValueError("Supply a valid length")
        return __PKCS7(pad_data, length)
    elif direction == UNPAD:
        return __PKCS7_unpad(pad_data)
    else:
        raise ValueError("Supply a valid direction")


def __PKCS7(to_pad, length):
    amount = length - len(to_pad) % length
    pattern = bytearray([amount])
    pad = pattern * amount
    return bytes(to_pad + pad)


def __PKCS7_unpad(padded):
    pattern = padded[-1:]
    length = bytearray(pattern)[0]
    # check if the bytes to be removed are all the same pattern
    if padded.endswith(pattern * length):
        return padded[:-length]
    else:
        print('error: padding pattern not recognized')
        return padded


def ANSI_X923(pad_data, direction, length=None):
    """Pad a string using ANSI_X923

        padData = raw string to pad/unpad
        direction = PAD or UNPAD
        length = amount of bytes the padded string should be a multiple of
                 (length variable is not used when unpadding)

        returns: (un)padded raw string

        A new block full of padding will be added when padding data that is
        already a multiple of the given length.

        Example:
        =========
        >>> from CryptoPlus.Util import padding

        >>> padding.ANSI_X923(b'12345678', padding.PAD, 16)
        b'12345678\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08'
        >>> padding.ANSI_X923(_, padding.UNPAD)
        b'12345678'"""
    if direction == PAD:
        if length is None:
            raise ValueError("Supply a valid length")
        return __ANSI_X923(pad_data, length)
    elif direction == UNPAD:
        return __ANSI_X923_unpad(pad_data)
    else:
        raise ValueError("Supply a valid direction")


def __ANSI_X923(to_pad, length):
    bytesToPad = length - len(to_pad) % length
    trail = bytes(bytearray([bytesToPad]))
    pattern = b'\x00' * (bytesToPad - 1) + trail
    return to_pad + pattern


def __ANSI_X923_unpad(padded):
    length = bytearray(padded)[-1]
    # check if the bytes to be removed are all zero
    if padded.count(b'\x00', -length, -1) == length - 1:
        return padded[:-length]
    else:
        print(f"error: padding pattern not recognized "
              f"{padded.count(chr(0), -length, -1)}")
        return padded


def ISO_10126(pad_data, direction, length=None):
    """Pad a string using ISO_10126

        padData = raw string to pad/unpad
        direction = PAD or UNPAD
        length = amount of bytes the padded string should be a multiple of
                 (length variable is not used when unpadding)

        returns: (un)padded raw string

        A new block full of padding will be added when padding data that is
        already a multiple of the given length.

        Example:
        =========
        >>> from CryptoPlus.Util import padding

        >>> padded = padding.ISO_10126(b'12345678',padding.PAD,16)
        >>> padding.ISO_10126(padded,padding.UNPAD)
        b'12345678'"""
    if direction == PAD:
        if length is None:
            raise ValueError("Supply a valid length")
        return __ISO_10126(pad_data, length)
    elif direction == UNPAD:
        return __ISO_10126_unpad(pad_data)
    else:
        raise ValueError("Supply a valid direction")


def __ISO_10126(toPad, length):
    bytes_to_pad = length - len(toPad) % length
    random_pattern = bytearray(
        random.randint(0, 255) for x in range(0, bytes_to_pad - 1))
    return bytes(toPad + random_pattern + bytearray([bytes_to_pad]))


def __ISO_10126_unpad(padded):
    return padded[0:len(padded) - bytearray(padded)[-1]]


def _test():
    import doctest
    doctest.testmod()


if __name__ == "__main__":
    _test()
