from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM, AESOCB3, AESSIV

aead_algorithms = {"chacha": ChaCha20Poly1305,
                   "aes-gcm": AESGCM,
                   "aes-ccm": AESCCM,
                   "aes-ocb3": AESOCB3,
                   #no nonce
                   #"aes-siv": AESSIV
                   }

from cryptography.hazmat.primitives.ciphers.algorithms import AES256    

encryption_algorithms = {"aes-256": AES256}

from cryptography.hazmat.primitives.hashes import SHA256, SHA512, SHA3_256, SHA3_512

hashes = {  'sha-256': SHA256,
            'sha-512': SHA512,
            'sha3-256': SHA3_256,
            'sha3-512': SHA3_512}



