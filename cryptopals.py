from binascii import b2a_base64, a2b_base64
from itertools import cycle, zip_longest
from Cryptodome.Cipher import AES
import copy 

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
    return bytes(text, 'ascii')

def xorBytes(bArr1, bArr2):
    xorBytes = bytearray()
    for b1, b2 in zip(bArr1, bArr2):
        xorBytes.append(b1 ^ b2)
    return xorBytes

def singleByteXOR(bArr, key):
    xorBytes = bytearray()
    for b in bArr:
        xorBytes.append(b ^ key)
    return xorBytes

def checkChallenge(expected, actual, num):
    if expected != actual:
        print(f'Failed challenge {num}.\nExpected: {expected}\nActual:   {actual}')
        quit()

def scoreEnglishText(text):
    letterList = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    score = 0
    for c in text:
        if c.isalpha():
            score += 26 - letterList.find(c.upper())
        elif ord(c) == 10:
            pass
        elif ord(c) >= 123:
            score -= 100
        elif ord(c) <= 31:
            score -= 100

    return score

# May return None if nothing can be turned into english
def breakSingleKey(encryptedBytes):
    bestScore, bestStr, bestKey = None, None, None
    for key in range(255):
        decrypted = singleByteXOR(encryptedBytes, key)
        try:
            decryptedText = bytesToStr(decrypted)
            score = scoreEnglishText(decryptedText)
            if bestScore == None or score > bestScore:
                bestScore = score
                bestStr = decryptedText
                bestKey = chr(key)
        except:
            pass

    return (bestStr, bestKey)

def repeatingKeyXOR(bArr, key):
    encBytes = bytearray()
    for b1, b2 in zip(bArr, cycle(key)):
        encBytes.append(b1 ^ b2)

    return encBytes

def hammingDist(bArr1, bArr2):
    dist = 0
    for b1, b2 in zip(bArr1, bArr2):
        mask = 0x80
        while mask > 0:
            if b1 & mask != b2 & mask:
                dist += 1
            mask >>= 1

    return dist

def findBestKeysizes(bArr, keySizes):
    distSizeArr = []
    for keysize in keySizes:
        distSum = 0
        for i in range(10):
            chunk1 = bArr[keysize * i : keysize * (i + 1)]
            chunk2 = bArr[keysize * (i + 1) : keysize * (i + 2)]
            distSum += hammingDist(chunk1, chunk2) / keysize
        distSizeArr.append((distSum / 10, keysize))

    numToReturn = 5
    if len(distSizeArr) < 5:
        numToReturn = len(distSizeArr)
        
    distSizeArr.sort()
    return [i[1] for i in distSizeArr[0:5]] #numToReturn]]

def readAllFromFile(name):
    with open(name, 'r') as data:
        nextLine = data.readline()
        fullData = '' + nextLine
        while nextLine != '':
            nextLine = data.readline()
            fullData += nextLine

    return fullData

def breakRepeatingKeyXor(encBytes, keySizes = range(2, 41)):
    bestSizes = findBestKeysizes(encBytes, keySizes)

    bestScore, bestKey, bestStr = None, None, None
    for keysize in bestSizes:
        fullKey = bytearray()
        for start in range(keysize):
            _, key = breakSingleKey(encBytes[start::keysize])
            if key is None:
                #This can't be the key because we haven't received English back
                break
            fullKey.append(ord(key))

        if len(fullKey) != keysize:
            #This key failed, at least in certain spots, can't be the key
            continue

        try:
            decBytes = repeatingKeyXOR(encBytes, fullKey)
            decStr = bytesToStr(decBytes)
            score = scoreEnglishText(decStr)
            if bestScore is None or score > bestScore:
                bestScore = score
                bestStr = decStr
                bestKey = fullKey
        except:
            print(f'Issue with {bytesToStr(fullKey)}')
            pass

    return bestKey, bestStr, bestScore

def ecbDecrypt(encBytes, keyBytes):
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    return cipher.decrypt(encBytes)


def ecbEncrypt(encBytes, keyBytes):
    cipher = AES.new(keyBytes, AES.MODE_ECB)
    return cipher.encrypt(pkcsPad(encBytes)

class set1:
    def challenge1(self):
        hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        actual = hexStrToBase64Str(hex)
        checkChallenge(expected, actual, 1)

    def challenge2(self):
        hex1 = '1c0111001f010100061a024b53535009181c'
        hex2 = '686974207468652062756c6c277320657965'
        expected = '746865206b696420646f6e277420706c6179'
        actual = bytesToHexStr(xorBytes(hexStrToBytes(hex1), hexStrToBytes(hex2)))
        checkChallenge(expected, actual, 2)

    def challenge3(self):
        hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        encrypted = hexStrToBytes(hex)
        actualStr, actualKey = breakSingleKey(encrypted)
        expectedStr = 'Cooking MC\'s like a pound of bacon'
        expectedKey = 'X'
        checkChallenge(expectedStr, actualStr, 3)
        checkChallenge(expectedKey, actualKey, 3)

    def challenge4(self):
        with open('4.txt', 'r') as data:
            bestStr, bestScore = None, None
            encryptedHex = data.readline()
            while(encryptedHex != ""):
                encBytes = hexStrToBytes(encryptedHex)
                decStr, key = breakSingleKey(encBytes)
                if decStr is not None:
                    score = scoreEnglishText(decStr)
                    if bestScore is None or score > bestScore:
                        bestStr = decStr
                        bestScore = score
                encryptedHex = data.readline()

        expectedStr = 'Now that the party is jumping\n'
        checkChallenge(expectedStr, bestStr, 4)

    def challenge5(self):
        key = 'ICE'
        line = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'

        expectedHex = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        encBytes = repeatingKeyXOR(strToBytes(line), strToBytes(key))

        checkChallenge(expectedHex, bytesToHexStr(encBytes), 5)

    def challenge6(self):
        fullData = readAllFromFile('6.txt')
        encBytes = hexStrToBytes(base64ToHexStr(fullData))
        breakRepeatingKeyXor(encBytes)
        # TODO: Actually check this with checkChallenge for posterity
        # print(f'Best Key: {bestKey}\nMessage: {bestStr}')

    def challenge7(self):
        b64Data = readAllFromFile('7.txt')
        key = 'YELLOW SUBMARINE'

        encBytes = hexStrToBytes(base64ToHexStr(b64Data))
        bArrKey = bytearray(strToBytes(key))

        plaintext = ecbDecrypt(encBytes, bArrKey)

        expected = None 
        with open('7_answer.txt', 'rb') as answer:
            expected = answer.read()
        checkChallenge(expected, plaintext, 7)

    def challenge8(self):
        bestScore = None
        bestLine = None

        with open('8.txt', 'r') as data:
            hexStr = data.readline()
            linenumber = 0

            while hexStr != '':
                byteArr = hexStrToBytes(hexStr)

                chunked = []
                for i in range(0, len(byteArr), 16):
                    chunked.append(bytes(byteArr[i:i+16]))

                score = 0
                for i in range(len(chunked)):
                    for j in range(i + 1, len(chunked)):
                        score += hammingDist(chunked[i], chunked[j])

                if bestScore is None or score < bestScore:
                    bestScore = score
                    bestLine = linenumber 

                hexStr = data.readline()
                linenumber += 1

        expectedLine = 132
        checkChallenge(expectedLine, bestLine, 8)

    def checkHam(self):
        s1 = 'this is a test'
        s2 = 'wokka wokka!!!'
        checkChallenge(37, hammingDist(strToBytes(s1), strToBytes(s2)), 'ham')

    def testSet1(self):
        self.challenge1()
        self.challenge2()
        self.challenge3()
        self.challenge4()
        self.challenge5()
        self.checkHam()
        self.challenge6()
        self.challenge7()
        self.challenge8()

def pkcsPad(block, size):
    padVal = size - len(block)
    paddedBlock = copy.copy(block)
    if size <= 0:
        return paddedBlock

    paddedBlock.extend([padVal] * padVal)
    return paddedBlock

def grouper(n, iterable):
    args = [iter(iterable)] * n
    return zip_longest(*args)

def cbcEncrypt(plaintextBytes, key):
    initVect = bytes([0] * 16)
    pTextPad = pkcsPad(plaintextBytes, len(plaintextBytes) % 16)
    prevEncBytes = initVect

    cipherBytes = bytearray()
    for block in grouper(16, pTextPad):
        xorBlock = xorBytes(prevEncBytes, block)
        currEncBytes = ecbEncrypt(xorBlock, key)
        cipherBytes.extend(currEncBytes)
        prevEncBytes = currEncBytes 

    return cipherBytes

def cbcDecrypt(encBytes, key):
    initVect = bytes([0] * 16)
    prevEncBytes = initVect

    decBytes = bytearray()
    for block in grouper(16, encBytes):
        decXorBlock = ecbDecrypt(bytearray(block), key)
        decPlainBlock = xorBytes(decXorBlock, prevEncBytes)
        decBytes.extend(decPlainBlock)
        prevEncBytes = block

    return decBytes

class set2:
    def challenge1(self):
        text = 'YELLOW SUBMARINE'
        bArr = bytearray(strToBytes(text))
        paddedArr = pkcsPad(bArr, 20)

        expected = bytearray(strToBytes('YELLOW SUBMARINE\x04\x04\x04\x04'))
        checkChallenge(expected, paddedArr, 1)

    def challenge2(self):
        encBytes = hexStrToBytes(base64ToHexStr(readAllFromFile("10.txt")))
        decBytes = cbcDecrypt(encBytes, strToBytes('YELLOW SUBMARINE'))
        expected = None
        with open("10_answer.txt", "rb") as answer:
            expected = answer.read()
        
        checkChallenge(expected, decBytes, 2)

    def testEcbEncryptDecrypt(self):
        keyBytesPad = pkcsPad(bytearray(strToBytes("ICE")), 16)
        expectedPad = pkcsPad(bytearray(strToBytes("Bringin' the noise")), 32)
        encBytes = ecbEncrypt(expectedPad, keyBytesPad)
        plaintext = ecbDecrypt(encBytes, keyBytesPad)

        checkChallenge(expectedPad, plaintext, "ECBTest")

    def testSet2(self):
        self.challenge1()
        self.testEcbEncryptDecrypt()
        self.challenge2()


if __name__ == '__main__':
    print('Testing Set 1')
    set1().testSet1()
    print('Set 1 Passed')

    print('Testing Set 2')
    set2().testSet2()
    print('Set 2 Passed')