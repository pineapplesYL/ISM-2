import binascii
import hashlib
import base64
from gmssl import sm4
from ecdsa import NIST192p, SigningKey, VerifyingKey, BadSignatureError
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1, SHA256, SHA3_256, RIPEMD160
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Util.Padding import pad, unpad
import hmac
import math
from RC6Encryption import RC6Encryption
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct

app = Flask(__name__)
CORS(app)

# 哈希算法
def hash_algorithm(algorithm, plaintext):
    if algorithm == "SHA1":
        return SHA1.new(plaintext.encode()).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(plaintext.encode()).hexdigest()
    elif algorithm == "SHA3":
        return SHA3_256.new(plaintext.encode()).hexdigest()
    elif algorithm == "RIPEMD160":
        return RIPEMD160.new(plaintext.encode()).hexdigest()
    elif algorithm == "HMACSHA1":
        key = plaintext
        return hmac.new(key.encode(), plaintext.encode(), SHA1).hexdigest()
    elif algorithm == "HMACSHA256":
        key = plaintext
        return hmac.new(key.encode(), plaintext.encode(), hashlib.sha256).hexdigest()
    elif algorithm == "PBKDF2":
        salt = get_random_bytes(16)
        return PBKDF2(plaintext, salt, dkLen=32).hex()

# 编码算法
def encode_algorithm(algorithm, plaintext):
    if algorithm == "Base64":
        return base64.b64encode(plaintext.encode()).decode('utf-8')
    elif algorithm == "UTF-8":
        return plaintext.encode('utf-8').decode('utf-8')

# 解码算法
def decode_algorithm(algorithm, ciphertext):
    if algorithm == "Base64":
        return base64.b64decode(ciphertext).decode('utf-8')
    elif algorithm == "UTF-8":
        return ciphertext.encode('utf-8').decode('utf-8')

# RSA 密钥生成 (1024bit)
def generate_rsa_key():
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return {'privatekey': private_key.decode(), 'publickey': public_key.decode()}

# ECC 密钥生成
def generate_ecc_key(password: bytes = None):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    # 序列化私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # 序列化公钥
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return {'privatekey': private_pem, 'publickey': public_pem}

# ECDSA 密钥生成 (160-bit, NIST192p curve)
def generate_ecdsa_key():
    sk = SigningKey.generate(curve=NIST192p)
    vk = sk.get_verifying_key()
    return {
        'privatekey': sk.to_string().hex(),
        'publickey': vk.to_string().hex()
    }

# RSA-SHA1 签名
def rsa_sha1_sign(private_key, plaintext):
    private_key = RSA.import_key(private_key)
    signer = pkcs1_15.new(private_key)
    h = SHA1.new(plaintext.encode())
    signature = signer.sign(h)
    return base64.b64encode(signature).decode('utf-8')

# RSA-SHA1 验证
def rsa_sha1_verify(public_key, plaintext, signature):
    public_key = RSA.import_key(public_key)
    verifier = pkcs1_15.new(public_key)
    h = SHA1.new(plaintext.encode())
    signature = base64.b64decode(signature)
    try:
        verifier.verify(h, signature)
        return 'valid'
    except (ValueError, TypeError):
        return 'invalid'

# ECDSA 签名 (使用 NIST192p 曲线)
def ecdsa_sign(private_key, plaintext):
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=NIST192p)
    signature = sk.sign(plaintext.encode())
    return signature.hex()

# ECDSA 验证
def ecdsa_verify(public_key, plaintext, signature):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=NIST192p)
    try:
        vk.verify(bytes.fromhex(signature), plaintext.encode())
        return 'valid'
    except BadSignatureError:
        return 'invalid'

# RSA 加密
def rsa_encrypt(public_key, plaintext):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode('utf-8')

# RSA 解密
def rsa_decrypt(private_key, ciphertext):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_v1_5.new(private_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext), None)
    return plaintext.decode('utf-8')

# ECC加密函数
def ecc_encrypt(public_key, plaintext):
    """加密：返回单个合并后的密文字节流"""
    print(public_key)
    # 生成临时密钥对
    ephemeral_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # ECDH密钥交换
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
    
    # 派生加密密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-v1',
        backend=default_backend()
    ).derive(shared_key)
    
    # AES-GCM加密
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # 序列化临时公钥
    ephemeral_pub_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 合并所有组件：格式 = [4字节长度] + 临时公钥PEM + 12字节IV + 16字节Tag + 密文
    merged = (
        struct.pack('>I', len(ephemeral_pub_bytes)) +  # 4字节长度头
        ephemeral_pub_bytes +
        iv +
        encryptor.tag +
        ciphertext
    )
    return merged.hex()

# ECC解密函数
def ecc_decrypt(private_key, merged_ciphertext):
    """解密：从合并的字节流中提取组件"""
    # 解析字节流
    ptr = 0
    
    # 读取临时公钥长度
    pubkey_len = struct.unpack('>I', merged_ciphertext[ptr:ptr+4])[0]
    ptr += 4
    
    # 提取临时公钥
    ephemeral_pub_bytes = merged_ciphertext[ptr:ptr+pubkey_len]
    ptr += pubkey_len
    
    # 加载临时公钥
    ephemeral_pub = serialization.load_pem_public_key(
        ephemeral_pub_bytes,
        backend=default_backend()
    )
    
    # 提取固定长度组件
    iv = merged_ciphertext[ptr:ptr+12]     # 12字节IV
    ptr += 12
    tag = merged_ciphertext[ptr:ptr+16]    # 16字节GCM标签
    ptr +=16
    
    # 剩余部分是密文
    ciphertext = merged_ciphertext[ptr:]
    
    # ECDH密钥交换
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
    
    # 派生密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecies-v1',
        backend=default_backend()
    ).derive(shared_key)
    
    # AES-GCM解密
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Process Key
def process_key(key, required_length):
    key_bytes = key.encode() if isinstance(key, str) else key
    if len(key_bytes) < required_length:
        return key_bytes.ljust(required_length, b'\0')
    return key_bytes[:required_length]

# RC6加密
def rc6_encrypt(key, plaintext):
    key = process_key(key, 16)
    rc6 = RC6Encryption(key)
    ciphertext = rc6.data_encryption_ECB(plaintext.encode())
    return ciphertext.hex()

# RC6解密
def rc6_decrypt(key, ciphertext):
    key = process_key(key, 16)
    rc6 = RC6Encryption(key)
    plaintext = rc6.data_decryption_ECB(bytes.fromhex(ciphertext))
    return plaintext.decode()

# SM4加密
def sm4_encrypt(key, plaintext):
    key = process_key(key, 16)
    sm4_crypt = sm4.CryptSM4()
    sm4_crypt.set_key(key, sm4.SM4_ENCRYPT)
    return sm4_crypt.crypt_ecb(plaintext.encode()).hex()

# SM4解密
def sm4_decrypt(key, ciphertext):
    key = process_key(key, 16)
    ciphertext = bytes.fromhex(ciphertext)
    sm4_crypt = sm4.CryptSM4()
    sm4_crypt.set_key(key, sm4.SM4_DECRYPT)
    return sm4_crypt.crypt_ecb(ciphertext).decode()

# AES 加密
def aes_encrypt(key, plaintext):
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext_base64

# AES 解密
def aes_decrypt(key, ciphertext):
    key = process_key(key, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_plaintext.decode('utf-8')

def encrypt(algorithm, data):
    if algorithm == "AES":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return aes_encrypt(key, plaintext)
    elif algorithm == "SM4":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return sm4_encrypt(key, plaintext)
    elif algorithm == "RC6":
        key = data.get('key')
        plaintext = data.get('plaintext')
        return rc6_encrypt(key, plaintext)
    elif algorithm == "RSA":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        return rsa_encrypt(public_key, plaintext)
    elif algorithm == "ECC":
        public_key = data.get('publickey')
        public_key = serialization.load_pem_public_key(
            public_key.encode('utf-8'),
            backend=default_backend()
        )
        plaintext = data.get('plaintext').encode()
        return ecc_encrypt(public_key, plaintext)
    else:
        return "Unsupported algorithm"

def decrypt(algorithm, data):
    if algorithm == "AES":
        key = data.get('key')
        ciphertext = base64.b64decode(data.get('ciphertext'))
        return aes_decrypt(key, ciphertext)
    elif algorithm == "SM4":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return sm4_decrypt(key, ciphertext)
    elif algorithm == "RC6":
        key = data.get('key')
        ciphertext = data.get('ciphertext')
        return rc6_decrypt(key, ciphertext)
    elif algorithm == "RSA":
        private_key = data.get('privatekey')
        ciphertext = data.get('ciphertext')
        return rsa_decrypt(private_key, ciphertext)
    elif algorithm == "ECC":
        private_key = data.get('privatekey')
        private_key = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        ciphertext = bytes.fromhex(data.get('ciphertext'))
        print(ciphertext)
        text = ecc_decrypt(private_key, ciphertext)
        print(text)
        return ecc_decrypt(private_key, ciphertext).decode()
    else:
        return "Unsupported algorithm"

# Route handling
@app.route('/encrypt', methods=['POST'])
def handle_encrypt():
    data = request.get_json()
    algorithm = data.get('algorithm')
    
    return jsonify({'ciphertext': encrypt(algorithm, data)})

@app.route('/decrypt', methods=['POST'])
def handle_decrypt():
    data = request.get_json()
    algorithm = data.get('algorithm')

    return jsonify({'plaintext': decrypt(algorithm, data)})
    
@app.route('/hash', methods=['POST'])
def handle_hash():
    data = request.get_json()
    algorithm = data.get('algorithm')
    plaintext = data.get('plaintext')
    return jsonify({'hash': hash_algorithm(algorithm, plaintext)})

@app.route('/encode', methods=['POST'])
def handle_encode():
    data = request.get_json()
    algorithm = data.get('algorithm')
    plaintext = data.get('plaintext')
    return jsonify({'encoded': encode_algorithm(algorithm, plaintext)})

@app.route('/decode', methods=['POST'])
def handle_decode():
    data = request.get_json()
    algorithm = data.get('algorithm')
    ciphertext = data.get('ciphertext')
    return jsonify({'decoded': decode_algorithm(algorithm, ciphertext)})

@app.route('/generate', methods=['POST'])
def handle_generate():
    data = request.get_json()
    algorithm = data.get('algorithm')

    if algorithm == "RSA" or algorithm == "RSA-SHA1":
        return jsonify(generate_rsa_key())
    elif algorithm == "ECC":
        return jsonify(generate_ecc_key())
    elif algorithm == "ECDSA":
        return jsonify(generate_ecdsa_key())

@app.route('/sign', methods=['POST'])
def handle_sign():
    data = request.get_json()
    algorithm = data.get('algorithm')

    if algorithm == "RSA-SHA1":
        private_key = data.get('privatekey')
        plaintext = data.get('plaintext')
        return jsonify({'signature': rsa_sha1_sign(private_key, plaintext)})
    elif algorithm == "ECDSA":
        private_key = data.get('privatekey')
        plaintext = data.get('plaintext')
        return jsonify({'signature': ecdsa_sign(private_key, plaintext)})

@app.route('/verify', methods=['POST'])
def handle_verify():
    data = request.get_json()
    algorithm = data.get('algorithm')

    if algorithm == "RSA-SHA1":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        signature = data.get('signature')
        return jsonify({'result': rsa_sha1_verify(public_key, plaintext, signature)})
    elif algorithm == "ECDSA":
        public_key = data.get('publickey')
        plaintext = data.get('plaintext')
        signature = data.get('signature')
        return jsonify({'result': ecdsa_verify(public_key, plaintext, signature)})

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
