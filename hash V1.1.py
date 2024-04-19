# hash.py V1.0
# ©Tobias Lippe 19.04.2024
# This programm inputs a file and outputs hash values of it. 
# Additionally it compares given value with the calculated ones and shows which algorithm matches. 

import hashlib
from tkinter import filedialog

def get_md5(bytes):
    hash = hashlib.md5()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha1(bytes):
    hash = hashlib.sha1()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha224(bytes):
    hash = hashlib.sha224()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha256(bytes):
    hash = hashlib.sha256()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha384(bytes):
    hash = hashlib.sha384()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha512(bytes):
    hash = hashlib.sha512()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_224(bytes):
    hash = hashlib.sha3_224()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_256(bytes):
    hash = hashlib.sha3_256()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_384(bytes):
    hash = hashlib.sha3_384()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_512(bytes):
    hash = hashlib.sha3_512()
    hash.update(bytes)
    return hash.hexdigest()

def get_all_hashes(bytes):
    hashes = {}
    hashes.update({"MD5"     :get_md5(bytes)})
    hashes.update({"SHA1"    :get_sha1(bytes)})
    hashes.update({"SHA224"  :get_sha224(bytes)})
    hashes.update({"SHA256"  :get_sha256(bytes)})
    hashes.update({"SHA384"  :get_sha384(bytes)})
    hashes.update({"SHA512"  :get_sha512(bytes)})
    hashes.update({"SHA3_224":get_sha3_224(bytes)})
    hashes.update({"SHA3_256":get_sha3_256(bytes)})
    hashes.update({"SHA3_384":get_sha3_384(bytes)})
    hashes.update({"SHA3_512":get_sha3_512(bytes)})
    return hashes


def dict_to_array(dict):
    array = list(dict)
    print(array)

def compare(bytes, hash_to_compare):
    hash_dict = get_all_hashes(bytes)
    value_array = list(hash_dict.values())

    count = 0
    for key in hash_dict.keys():
        if value_array[count] == hash_to_compare:
            return f"match: {key}"#: {value_array[count]}"
        count += 1
    
    return False


def Start():
    file = filedialog.askopenfilename() #"D:/#/##/BlueJ/Bank-Mey/README.TXT"

    if file != "":
        print(f"File: {file}")
        with open(str(file), "rb") as file:
            bytes = file.read()
    elif file == "":
        print("Cancel")
        return 1
    else:
        print("Error")
        return 1
        

    mode = input("1: return, 2: compare: ")
    if mode == "1":
        #print(get_all_hashes(bytes))
        hash_dict = get_all_hashes(bytes)
        value_array = list(hash_dict.values())

        count = 0
        for key in hash_dict.keys():
            print(f"{key}: {value_array[count]}")
            count +=1
    
    elif mode == "2":
        hash_to_compare = input("Input hash: ")
        result = compare(bytes, hash_to_compare)
        if not result:
            print("No match")
        else:
            print(result)
    
    print()


error = 0
if __name__ == "__main__":
    while True and error == 0:
        error = Start()