import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

privateKeyFile = 'private.pem'

def scanRecurse(baseDir):
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)

def decrypt(dataFile, privateKeyFile):
    # read private key from file
    extension = dataFile.suffix.lower()
    with open(privateKeyFile, 'rb') as f:
        privateKey = f.read()
        # create private key object
        key = RSA.import_key(privateKey)

    # read data from file
    with open(dataFile, 'rb') as f:
        # read from session key
        encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in(key.size_in_bytes(), 16, 16, -1)]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    dataFile = str(dataFile)
    fileName = dataFile.split(extension)[0]
    fileExtension = '.decrypted' # mark file as decrypted
    decryptFile = fileName + fileExtension
    with open(decryptFile, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to ' + decryptFile)

directory = './' # change this

dir = input('put your directory (default is "./"):')
if dir:
    directory = dir

includeExtension = ['.y0urd00m3d'] # all lower case characters

for item in scanRecurse(directory):
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    # run the decryptor just if the extension is the one that I mention
    if fileType in includeExtension:
        decrypt(filePath, privateKeyFile)