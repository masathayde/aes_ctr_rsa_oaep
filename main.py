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
    outputfilename = "64out.txt"
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
    hashF = hashlib.sha3_256()
    # Preparing AES CTR class
    AES_obj = AES_128_CTR(aesKey, (nonce << 32))
    with open(filename, "rb") as f:
        buffer = f.read(bufferSize)
        cipherFilestream = b''
        while buffer != b'':
            hashF.update(buffer)
            cipherFilestream += AES_obj.execute(buffer)
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
    rNonce = int.from_bytes(rFullKey[16:], 'big')

    # Decrypt file.
    fileSize = len(rEncFile)
    chunks = fileSize//4096
    lastChunkSize = fileSize % 4096
    rHashF = hashlib.sha3_256()
    rAES_obj = AES_128_CTR(rAesKey, (rNonce << 32))
    with open("output", "wb") as f:
        for i in range(chunks):
            buffer = rEncFile[i*4096 : i*4096 + 4096]
            decStream = rAES_obj.execute(buffer)
            f.write(decStream)
            rHashF.update(decStream)
        # Last chunk
        buffer = rEncFile[-lastChunkSize:]
        decStream = rAES_obj.execute(buffer)
        rHashF.update(decStream)
        f.write(decStream)

    # Verifying hash.
    decFileHash = rHashF.digest()
    print(rFileHash)
    print(decFileHash)
    assert decFileHash == rFileHash

i_filename = "0Un50tpnwq1E66QE.mp4"
o64_filename = "64out.txt"
part_I(i_filename)
# part_II(o64_filename,
# 22855085205406304079233762371536935517343293589097210458391260486802169898375737989745997420932662792355991910340952623359977202451966654789932155516035145432942014116082967047599273318053581894570538125225526326860906857495731630237003726605115281280644430020287636533695314292836591382621794713687211013372836419413744474569352552269037703912824857930965808792778427021388962981616810364998745496939655019263393632118434638721347638829773340908195500862450202619858156973806023226218985848608796006031207566762164719470000340741669667374052134157599514392526918568028742391477064555480185951151339304748742151573193,
# 24724810074226456321961391930529640365793358180760698598761790636066651402747573342037659216184346930929410901570046913671659858983749668294808333900965572147021686322869041636792287605772067094047132881809566017125555086903447679154231743129354751312946204424482772412287512797900854879300185869347134385094908247803144959759980437019883066987626933865821994327987725669640616896454841861841815050815632718048552262022416466187857239752862197826055151150842128924279693705707218038524270933632785474244734101468593168982339936101477049037098240454414596626063703306323352068824531133436118647020138158158899971205319)