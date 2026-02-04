import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data + salt)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    return ms[:key_len], ms[key_len:key_len + iv_len]


def enc(password, key="onepass987655432", salt=None):
    try:
        if salt is None:
            salt = os.urandom(8)
            # print(salt)
        elif isinstance(salt, str):
            salt = extract_salt_from_encrypted(salt)
        
        aes_key, iv = evp_bytes_to_key(key.encode('utf-8'), salt)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_password = pad(password.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_password)
        salted_data = b"Salted__" + salt + encrypted
        result = base64.b64encode(salted_data).decode('utf-8')
        return result
    except Exception as e:
        print(f"암호화 오류: {e}")
        return None


def extract_salt_from_encrypted(encrypted_str):
    decoded = base64.b64decode(encrypted_str)
    if decoded[:8] == b"Salted__":
        return decoded[8:16]
    raise ValueError("잘못된 형식")
