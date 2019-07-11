from itertools import cycle
import conversions as conv

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
            decryptedText = conv.bytesToStr(decrypted)
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
            decStr = conv.bytesToStr(decBytes)
            score = scoreEnglishText(decStr)
            if bestScore is None or score > bestScore:
                bestScore = score
                bestStr = decStr
                bestKey = fullKey
        except:
            print(f'Issue with {conv.bytesToStr(fullKey)}')
            pass

    return bestKey, bestStr, bestScore

