import base64
import time
import os
import rsa
import rsa_oaep
import random
import hashlib
from aes_128 import AES_128_Key_Expansion
from aes_ctr import AES_128_CTR

def printProgressBar (currentRound, totalRounds, prefix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):

    percent = ("{0:." + str(decimals) + "f}").format(100 * (currentRound / float(totalRounds)))
    filledLength = int(length * currentRound // totalRounds)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}%', end = printEnd)
    if currentRound == totalRounds: 
        print()

def encryptFileWithAES (filename: str, key: bytes, nonce: int, bufferSize = 256 * 1024):
    fileSize = os.path.getsize(filename)
    total = fileSize/bufferSize
    it = 0
    start_time = time.time()
    round_keys = AES_128_Key_Expansion(key)
    with open(filename, "rb") as f, open(filename + ".aes", "wb") as o:
        bytestream = f.read(bufferSize)
        while bytestream != b'':
            printProgressBar(it, total, 'Encrypt: ')
            stream = AES_128_CTR(bytestream, key, nonce, round_keys)
            o.write(stream)
            bytestream = f.read(bufferSize)
            it +=1
    print("Created file " + filename + ".aes")
    print("Time elapsed: %s seconds" % (time.time() - start_time))


def part_I(filename):
    # Create RSA keys and save them in a txt file.
    keyfilename = "rsa_keys.txt"
    outputfilename = "part_I_out.txt"
    N, e, d = rsa.RSA_2048()
    with open(keyfilename, "w") as f:
        f.write(f'N: {N}\n')
        f.write(f'e: {e}\n')
        f.write(f'd: {d}\n')

    # Generate AES key and nonce.
    aesKey = random.getrandbits(128).to_bytes(16, 'big')
    nonce = (1 << 95) + random.getrandbits(95)
    nonceB = nonce.to_bytes(12, 'big')
    fullKey = aesKey + nonceB

    # Encrypting full key with RSA-OAEP.
    encKey = rsa_oaep.RSA_OAEP_enc(fullKey, e, N)
    encKey = encKey.to_bytes(256, 'big')
    
    # Hash file and encrypt it.
    bufferSize = 4096
    round_keys = AES_128_Key_Expansion(aesKey)
    hashF = hashlib.sha3_256()
    with open(filename, "rb") as f:
        buffer = f.read(bufferSize)
        cipherFilestream = b''
        while buffer != b'':
            hashF.update(buffer)
            cipherFilestream += AES_128_CTR(buffer, nonce, round_keys)
            buffer = f.read(bufferSize)
    filehash = hashF.digest()

    # Encrypting file hash with RSA OAEP
    encHash = rsa_oaep.RSA_OAEP_enc(filehash, e, N)

    # Join everything.
    payload = encHash.to_bytes(256, 'big') + encKey + cipherFilestream
    # Base64 encoding.
    b64payload = base64.b64encode(payload)
    b64str = b64payload.decode('ascii')

    # Write to output file.
    with open(outputfilename, "w") as f:
        f.write(b64str)
    

# Part II - Decrypt and verify.
def part_II (outputfilename, rsaPriK, rsaN):
    # Open file and get b64 string.
    bufferSize = 4096
    with open(outputfilename, "r") as f:
        b64input = ''
        buffer = f.read(bufferSize)
        while buffer != '':
            b64input += buffer
            buffer = f.read(bufferSize)
    
    rPayload = base64.b64decode(b64input)

    # rsaPriK = d
    # rsaN = N

    # Separating the payload.
    rEncHash = rPayload[:256]
    rEncKey = rPayload[256:512]
    rEncFile = rPayload[512:]

    # Decrypting hash and keys.
    validEncHash, rFileHash = rsa_oaep.RSA_OAEP_dec(int.from_bytes(rEncHash, 'big'), rsaPriK, rsaN)
    validEncKey, rFullKey = rsa_oaep.RSA_OAEP_dec(int.from_bytes(rEncKey, 'big'), rsaPriK, rsaN)

    # Check if valid decrypted RSA_OAEP blocks.
    assert validEncHash == True
    assert validEncKey == True

    # Retrieve AES key and nonce.
    rAesKey = rFullKey[:16]
    rNonceB = int.from_bytes(rFullKey[16:], 'big')

    # Decrypt file.
    fileSize = len(rEncFile)
    chunks = fileSize//4096
    lastChunkSize = fileSize % 4096
    rHashF = hashlib.sha3_256()
    round_keys = AES_128_Key_Expansion(rAesKey)
    with open("output", "wb") as f:
        for i in range(chunks):
            buffer = rEncFile[i*4096 : i*4096 + 4096]
            decStream = AES_128_CTR(buffer, rNonceB, round_keys)
            f.write(decStream)
            rHashF.update(decStream)
        # Last chunk
        buffer = rEncFile[-lastChunkSize:]
        decStream = AES_128_CTR(buffer, rNonceB, round_keys)
        rHashF.update(decStream)
        f.write(decStream)

    # Verifying hash.
    decFileHash = rHashF.digest()
    assert decFileHash == rFileHash
    print(rFileHash)
    print(decFileHash)

i_filename = "input.txt"
o_filename = "out.txt"
# part_I(i_filename)
part_II(o_filename,
17424914344084347532024104044748437442174727859999216217478093655824434942935082992961833667553899937930372503246431523418279333455912410010270888385313207320223397950662929171586203443080779522137970710341499285013985619613986681117562854054071464427740452968837470991075645926699106393313714671817218453260758487488506075222563781593937714240939857765775379292224499568198927578115293610649932901436686623847747847062995991142619605023025581172061254863644741276166154534118539432659288188051434521579887029607062566649875507822515135707139978268294530613018126609352041528681797823786435186544147110369682707991617,
18395834456139951097107891793883152560453061306111160688889168850829053655967275590543182658437448697318580217553100659658232750357616734025631032122624306004469873892403047603309465753554963876773674835588305658074705621196588890112466844391598981349283579790242941723994403928897183151818694520552934143680004977054326588102615722562723703018046998678694689116803495351651056733333397759192118434713929406844983454910565825658816330887511577410275705034556075630793522625830219786628615910294903516977380578564414704667802853306082404411226123927468840894604960005418934287601906832163302794805450248572955674567117)