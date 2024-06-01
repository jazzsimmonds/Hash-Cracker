import hashlib
import os
import pyfiglet

def sha1(wordlist, h):
    pt = ''
    with open(wordlist, 'r', errors='replace') as file:
        for line in file.readlines():
            hash_ob = hashlib.sha1(line.strip().encode())
            hashed_pass = hash_ob.hexdigest()
            if hashed_pass == h:
                pt = line.strip()
                break
    return pt

def sha256(wordlist, h):
        with open(wordlist, 'r', errors='replace') as file:
            for line in file.readlines():
                hash_ob = hashlib.sha256(line.strip().encode())
                hashed_pass = hash_ob.hexdigest()
                if hashed_pass == h:
                    pt = line.strip()
                    break
            return pt

def md5(wordlist, h):
        with open(wordlist, 'r', errors='replace') as file:
            for line in file.readlines():
                hash_ob = hashlib.md5(line.strip().encode())
                hashed_pass = hash_ob.hexdigest()
                if hashed_pass == h:
                    pt = line.strip()
                    break
        return pt

def sha224(wordlist, h):
    pt = ''
    with open(wordlist, 'r', errors='replace') as file:
        for line in file.readlines():
            hash_ob = hashlib.sha224(line.strip().encode())
            hashed_pass = hash_ob.hexdigest()
            if hashed_pass == h:
                pt = line.strip()
                break
    return pt

def identify_hash(h):
    hash_type = ''
    if len(h) == 32:
        hash_type = 'md5'
    elif len(h) == 40:
        hash_type = 'sha1'
    elif len(h) == 64:
        hash_type = 'sha256'
    elif len(h) == 56:
        hash_type = 'sha224'
    return hash_type

def print_pt(pt):
    if pt == '':
        print("Plain text not found")
    else:
        print("\nPlaintext Found!")
        print("Plain text:",pt)
 
ascii_banner = pyfiglet.figlet_format("Hash Cracker")
print(ascii_banner)
print("By Jasmine Simmonds")
while True:
    wordlist_location = str(input('Enter wordlist location: '))
    is_file = os.path.isfile(wordlist_location)
    if is_file ==  False:
        print("File path does not exist, please try again")
    else:
        break

hash_input = str(input('Enter hash to be cracked: '))
hash_type = identify_hash(hash_input)
if hash_type == 'md5':
    pt = md5(wordlist_location, hash_input)
    print_pt(pt)
elif hash_type == 'sha1':
    pt = sha1(wordlist_location, hash_input)
    print_pt(pt)
elif hash_type == 'sha256':
    pt = sha256(wordlist_location, hash_input)
    print_pt(pt)
elif hash_type == 'sha224':
    pt = sha224(wordlist_location, hash_input)
    print_pt(pt)
else:
    print("Invalid hash type, only MD5, SHA-1, SHA-224, and SHA-256 are accepted.")


