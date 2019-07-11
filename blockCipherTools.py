import copy 
from itertools import zip_longest
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes, random
import basicCryptUtils as utils
import conversions as conv 

def pkcsPad(block, boundary):
    padSize = 0 
    paddedBlock = copy.copy(block)

    if len(block) < boundary:
        padSize = boundary - len(block)
    elif len(block) > boundary:
        padSize = boundary - len(block) % boundary

    paddedBlock.extend([padSize] * padSize)
    return paddedBlock

def grouper(n, iterable):
    args = [iter(iterable)] * n
    return zip_longest(*args)

def ecbDecrypt(encBytes, keyBytes):
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    return cipher.decrypt(encBytes)

def ecbEncrypt(encBytes, keyBytes):
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    return cipher.encrypt(encBytes)

def cbcEncrypt(plaintextBytes, key, IV = bytearray([0] * 16)):
    pTextPad = pkcsPad(plaintextBytes, 16)
    prevEncBytes = IV 

    cipherBytes = bytearray()
    for block in grouper(16, pTextPad):
        xorBlock = utils.xorBytes(prevEncBytes, block)
        currEncBytes = ecbEncrypt(xorBlock, key)
        cipherBytes.extend(currEncBytes)
        prevEncBytes = currEncBytes 

    return cipherBytes

def cbcDecrypt(encBytes, key, IV = bytearray([0] * 16)):
    prevEncBytes = IV 

    decBytes = bytearray()
    for block in [bytearray(nonBytes) for nonBytes in grouper(16, encBytes)]:
        decXorBlock = ecbDecrypt(block, key)
        decPlainBlock = utils.xorBytes(decXorBlock, prevEncBytes)
        decBytes.extend(decPlainBlock)
        prevEncBytes = block

    return decBytes

# This class will randomly choose between ECB and CBC each
# time EncryptRandomCipher is called, and expose the last
# mode as a property for checking in the challenges.
class RandomModeBlockCipher:
    def __init__(self):
        # Doesn't matter, it will get replaced each time
        self._lastMode = 'CBC'        

    @property
    def lastMode(self):
        return self._lastMode

    def EncryptRandomCipher(self, pTextBytes):
        # Encrypts with random key with random data appended front and back
        randKey = bytearray(get_random_bytes(16))
        randByteCount = random.randint(5, 10)
        randBytesStart = bytearray(get_random_bytes(randByteCount))
        randBytesEnd = bytearray(get_random_bytes(randByteCount))

        bytesToEnc = pkcsPad(randBytesStart + pTextBytes + randBytesEnd, 16)
        if random.randint(0, 1) == 0:
            #use ECB
            self._lastMode = 'ECB'
            return ecbEncrypt(bytesToEnc, randKey)
        else:
            #use CBC
            self._lastMode = 'CBC'
            return cbcEncrypt(bytesToEnc, randKey, bytearray(get_random_bytes(16)))

# Accepts a block cipher function in an unknown mode that just accepts plaintext and
# returns ciphertext, and determines which mode it's using
def determineBlockCipherType(unknownModeCipherFunc):
    # 5 bytes at start and end. Thus, we need 11 bytes to 
    # complete first block, 16 for another, 16 for one more so we can
    # check their equality, and the end doesn't matter here
    plaintextBytes = conv.strToBytes('A' * 43)
    ciphertext = unknownModeCipherFunc(plaintextBytes)

    # Add each block to a set. If the set is smaller than the 
    # number of 16-byte blocks, then there was a repeat block, therefore
    # it must be ECB since our plaintext is long enough to have repeats
    uniqueBlocks = set()
    [uniqueBlocks.add(block) for block in grouper(16, ciphertext)]
    guessedMode = "CBC"
    if len(uniqueBlocks) < len(ciphertext) / 16:
        guessedMode = "ECB"

    return guessedMode
