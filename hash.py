from hashlib import md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512
from tkinter.filedialog import askopenfilename
from time import sleep

def get_md5(bytes:bytes):
    hash = md5()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha1(bytes:bytes):
    hash = sha1()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha224(bytes:bytes):
    hash = sha224()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha256(bytes:bytes):
    hash = sha256()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha384(bytes:bytes):
    hash = sha384()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha512(bytes:bytes):
    hash = sha512()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_224(bytes:bytes):
    hash = sha3_224()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_256(bytes:bytes):
    hash = sha3_256()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_384(bytes:bytes):
    hash = sha3_384()
    hash.update(bytes)
    return hash.hexdigest()

def get_sha3_512(bytes:bytes):
    hash = sha3_512()
    hash.update(bytes)
    return hash.hexdigest()

def get_all_hashes(bytes:bytes):
    hashes = {}
    print("Generate MD5", end="\r")
    hashes.update({"MD5"     :get_md5(bytes)})
    
    print("Generate SHA1", end="\r")
    hashes.update({"SHA1"    :get_sha1(bytes)})
    
    print("Generate SHA224", end="\r")
    hashes.update({"SHA224"  :get_sha224(bytes)})
    
    print("Generate SHA256", end="\r")
    hashes.update({"SHA256"  :get_sha256(bytes)})
    
    print("Generate SHA384", end="\r")
    hashes.update({"SHA384"  :get_sha384(bytes)})
    
    print("Generate SHA512", end="\r")
    hashes.update({"SHA512"  :get_sha512(bytes)})
    
    print("Generate SHA3_224", end="\r")
    hashes.update({"SHA3_224":get_sha3_224(bytes)})
    
    print("Generate SHA3_256", end="\r")
    hashes.update({"SHA3_256":get_sha3_256(bytes)})
    
    print("Generate SHA3_384", end="\r")
    hashes.update({"SHA3_384":get_sha3_384(bytes)})
    
    print("Generate SHA3_512", end="\r")
    hashes.update({"SHA3_512":get_sha3_512(bytes)})
    print("                 ")
    return hashes


def compare_to_hash(hash_dict:dict, hash_to_compare:str):
    value_array = list(hash_dict.values())

    count = 0
    for key in hash_dict.keys():
        if value_array[count] == hash_to_compare:
            return f"match: {key}"#: {value_array[count]}"
        count += 1
    
    return False


def get_bytes(file_path:str):
    if file_path != "":
        with open(str(file_path), "rb") as file:
            file_bytes = file.read()
        return file_bytes
    elif file_path == "":
        print("Cancel")
        return 1
    else:
        print("Error")
        return 1


def print_dict(hash_dict:str, orig_value_array:list): 
    print("Hashes: ")
    count = 0
    for key in hash_dict.keys():
        print(f"- {key}: {orig_value_array[count]}")
        count +=1


def input_file():
    print("To select a file, please continue in new window")
    compare_file = askopenfilename()
    if compare_file == "":
        print("No file selected -> exit program")
        sleep(2)
        exit
    else: 
        print(f"selected file: {compare_file}")
        return compare_file


def main():
    print("Following hash types are supportet: md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512\n")
    
    orig_file = input_file()

    orig_bytes = get_bytes(orig_file)

    orig_hash_dict = get_all_hashes(orig_bytes)
    orig_value_array = list(orig_hash_dict.values())

    print_dict(orig_hash_dict, orig_value_array)    
    print()
    mode = input("1: compare to hash, 2: compare to file. Input: ")
    while not mode == "1" and not mode == "2": 
        mode = input("- Not the right input! Try again: ")
    print()

    if mode == "1": 
        hash_to_compare = input("Input hash to compare: ")
        result = compare_to_hash(orig_hash_dict, hash_to_compare)
        if result:
            print(f"Found {result}")
        else:
            print("No match found")
    
    elif mode == "2": 
        compare_file = input_file()
        print(f"compare {orig_file}")
        print(f"     to {compare_file}")
        print("     using sha256")
        comp_bytes = get_bytes(compare_file)
        
        if get_sha256(comp_bytes) == orig_hash_dict["SHA256"]:
            print("Files are the same")
        else:
            print("Files are not the same")
        
    print()


if __name__ == "__main__":
    try: 
        new = True
        while new:
            main()
            if input("do it again?") == "y":
                new = True
            else:
                new = False
    
    except Exception as a:
        #print(a)
        exit