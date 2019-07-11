import basicCryptUtils as utils
import conversions as conv
import blockCipherTools as blockTools

def checkChallenge(expected, actual, num):
    if expected != actual:
        print(f'Failed challenge {num}.\nExpected: {expected}\nActual:   {actual}')
        quit()

def readAllFromFile(name):
    with open(name, 'r') as data:
        nextLine = data.readline()
        fullData = '' + nextLine
        while nextLine != '':
            nextLine = data.readline()
            fullData += nextLine

    return fullData

class set1:
    def challenge1(self):
        hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        actual = conv.hexStrToBase64Str(hex)
        checkChallenge(expected, actual, 1)

    def challenge2(self):
        hex1 = '1c0111001f010100061a024b53535009181c'
        hex2 = '686974207468652062756c6c277320657965'
        expected = '746865206b696420646f6e277420706c6179'
        actual = conv.bytesToHexStr(utils.xorBytes(conv.hexStrToBytes(hex1), conv.hexStrToBytes(hex2)))
        checkChallenge(expected, actual, 2)

    def challenge3(self):
        hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        encrypted = conv.hexStrToBytes(hex)
        actualStr, actualKey = utils.breakSingleKey(encrypted)
        expectedStr = 'Cooking MC\'s like a pound of bacon'
        expectedKey = 'X'
        checkChallenge(expectedStr, actualStr, 3)
        checkChallenge(expectedKey, actualKey, 3)

    def challenge4(self):
        with open('data/s1-4.txt', 'r') as data:
            bestStr, bestScore = None, None
            encryptedHex = data.readline()
            while(encryptedHex != ""):
                encBytes = conv.hexStrToBytes(encryptedHex)
                decStr, key = utils.breakSingleKey(encBytes)
                if decStr is not None:
                    score = utils.scoreEnglishText(decStr)
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
        encBytes = utils.repeatingKeyXOR(conv.strToBytes(line), conv.strToBytes(key))

        checkChallenge(expectedHex, conv.bytesToHexStr(encBytes), 5)

    def challenge6(self):
        fullData = readAllFromFile('data/s1-6.txt')
        encBytes = conv.hexStrToBytes(conv.base64ToHexStr(fullData))
        utils.breakRepeatingKeyXor(encBytes)
        # TODO: Actually check this with checkChallenge for posterity
        # print(f'Best Key: {bestKey}\nMessage: {bestStr}')

    def challenge7(self):
        b64Data = readAllFromFile('data/s1-7.txt')
        key = 'YELLOW SUBMARINE'

        encBytes = conv.hexStrToBytes(conv.base64ToHexStr(b64Data))
        bArrKey = conv.strToBytes(key)

        plaintext = blockTools.ecbDecrypt(encBytes, bArrKey)

        expected = None 
        with open('answers/s1-7.txt', 'rb') as answer:
            expected = answer.read()
        checkChallenge(expected, plaintext, 7)

    def challenge8(self):
        bestScore = None
        bestLine = None

        with open('data/s1-8.txt', 'r') as data:
            hexStr = data.readline()
            linenumber = 0

            while hexStr != '':
                byteArr = conv.hexStrToBytes(hexStr)

                chunked = []
                for i in range(0, len(byteArr), 16):
                    chunked.append(byteArr[i:i+16])

                score = 0
                for i in range(len(chunked)):
                    for j in range(i + 1, len(chunked)):
                        score += utils.hammingDist(chunked[i], chunked[j])

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
        checkChallenge(37, utils.hammingDist(conv.strToBytes(s1), conv.strToBytes(s2)), 'ham')

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

class set2:
    def challenge1(self):
        text = 'YELLOW SUBMARINE'
        bArr = conv.strToBytes(text)
        paddedArr = blockTools.pkcsPad(bArr, 20)

        expected = conv.strToBytes('YELLOW SUBMARINE\x04\x04\x04\x04')
        checkChallenge(expected, paddedArr, 1)

    def challenge2(self):
        encBytes = conv.hexStrToBytes(conv.base64ToHexStr(readAllFromFile("data/s2-2.txt")))
        decBytes = blockTools.cbcDecrypt(encBytes, conv.strToBytes('YELLOW SUBMARINE'))
        expected = None
        with open("answers/s2-2.txt", "rb") as answer:
            expected = answer.read()
        
        checkChallenge(expected, decBytes, 2)

    def testEcbEncryptDecrypt(self):
        keyBytesPad = blockTools.pkcsPad(conv.strToBytes("ICE"), 16)
        expectedPad = blockTools.pkcsPad(conv.strToBytes("Bringin' the noise"), 16)
        encBytes = blockTools.ecbEncrypt(expectedPad, keyBytesPad)
        plaintext = blockTools.ecbDecrypt(encBytes, keyBytesPad)

        checkChallenge(expectedPad, plaintext, "ECBTest")

    def challenge3(self):
        randCipher = blockTools.RandomModeBlockCipher()
        for _ in range(100):
            guessedMode = blockTools.determineBlockCipherType(randCipher.EncryptRandomCipher)
            checkChallenge(randCipher.lastMode, guessedMode, 3)

    def challenge4(self):
        checkChallenge('unimplemented', '', 4)

    def testSet2(self):
        self.challenge1()
        self.testEcbEncryptDecrypt()
        self.challenge2()
        self.challenge3()
        self.challenge4()

if __name__ == '__main__':
    print('Testing Set 1')
    set1().testSet1()
    print('Set 1 Passed')

    print('Testing Set 2')
    set2().testSet2()
    print('Set 2 Passed')