from binascii import b2a_base64, a2b_base64

def hexStrToBase64Str(hex):
    return b2a_base64(hexStrToBytes(hex), newline=False).decode('ascii')

def base64ToHexStr(b64):
    return bytesToHexStr(a2b_base64(b64))

def hexStrToBytes(hex):
    return bytearray.fromhex(hex)

def bytesToHexStr(byteArray):
    return byteArray.hex()

def bytesToStr(byteArr):
    return byteArr.decode('ascii')

def strToBytes(text):
    return bytearray(bytes(text, 'ascii'))