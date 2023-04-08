import os.path
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

command = sys.argv[1]
masterPassword = sys.argv[2]
lines = []

if not os.path.isfile("passwords.bin"):
    file1 = open("passwords.bin", "w")
    file1.close()


def decodeUTF8(data: bytes):
    return data.decode('utf-8')


def encodeUTF8(data: str):
    return bytes(data, 'utf-8')


def refreshFile(fileRefresh):
    fileRefresh.seek(0)
    fileRefresh.truncate()


def generateRandomSalt(numOfBytes: int):
    return get_random_bytes(numOfBytes)


def PBKDF(masterPBKDF: str):
    saltPBKDF = generateRandomSalt(16)
    keyPBKDF = PBKDF2(masterPBKDF, saltPBKDF)
    return keyPBKDF, saltPBKDF


def pbkdf_key(masterPBKDF: str, salt):
    keyPBKDF = PBKDF2(masterPBKDF, salt)
    return keyPBKDF


def search_for_address(dataSearch, addressSearch):
    dataPutList = dataSearch.split()
    for address, password in zip(dataPutList[::2], dataPutList[1::2]):
        if addressSearch == address:
            print("Password for " + address + " is: " + password)
            break
    else:
        print("Address not found")


def refresh_string(dataRefresh, masterPasswordRefresh, fileRefresh):
    dataRefreshB = encodeUTF8(dataRefresh)
    newKey, newSalt = PBKDF(masterPasswordRefresh)
    encryptEAX(newKey, newSalt, dataRefreshB, fileRefresh)


def address_exists_check(dataSearch: str):
    addressCheck = sys.argv[3]
    addressPasswordCheck = sys.argv[4]

    dataSearchList = dataSearch.split()
    for i in range(0, len(dataSearchList), 2):
        if dataSearchList[i] == addressCheck:
            dataSearchList[i + 1] = addressPasswordCheck
            print("Stored new password for " + dataSearchList[i])
            break
    else:
        dataSearchList.append(addressCheck)
        dataSearchList.append(addressPasswordCheck)
        print("Stored password for " + addressCheck)

    return ' '.join(dataSearchList)


def encryptEAX(keyEAX: bytes, saltEAX: bytes, dataEAX: bytes, fileEAX):
    refreshFile(fileEAX)
    cipher = AES.new(keyEAX, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(dataEAX)
    [fileEAX.write(x) for x in (cipher.nonce, tag, saltEAX, ciphertext)]


def decryptEAX(fileEAX, masterPasswordEAX: str):
    try:
        nonce, tag, oldSalt, ciphertext = [fileEAX.read(x) for x in (16, 16, 16, -1)]
        oldKey = pbkdf_key(masterPasswordEAX, oldSalt)

        cipher = AES.new(oldKey, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        dataString = decodeUTF8(data)
        return dataString

    except ValueError:
        print("Wrong master password or detected tampering with file")
        quit()


def initCommand(masterInit, fileInit):
    if fileInit.readline() != b'':
        print("Password manager already initialized")
    else:
        key, salt = PBKDF(masterInit)
        encryptEAX(key, salt, b'', fileInit)
        print("Password manager initialized")


def putCommand(masterPasswordPut: str, filePut):
    dataPut = decryptEAX(filePut, masterPasswordPut)
    dataPut = address_exists_check(dataPut)

    refresh_string(dataPut, masterPasswordPut, filePut)


def get_command(masterPasswordGet: str, fileGet):
    addressGet = sys.argv[3]

    dataGet = decryptEAX(fileGet, masterPasswordGet)
    search_for_address(dataGet, addressGet)

    refresh_string(dataGet, masterPasswordGet, fileGet)


with open('passwords.bin', 'rb+') as file:
    if command == "init":
        initCommand(masterPassword, file)

    elif command == "put":
        putCommand(masterPassword, file)

    elif command == "get":
        get_command(masterPassword, file)

    else:
        print("Wrong command")
file.close()
