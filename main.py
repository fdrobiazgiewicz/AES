from Crypto.Cipher import AES
import os, sys, struct
from time import time

KEY = b'Sixteen byte key'  # 128 bits key

INPUT_PATH, OUTPUT_PATH = sys.argv[1], sys.argv[2]


def timer(func):
    def wrap_func(*args, **kwargs):
        t1 = time()
        result = func(*args, **kwargs)
        t2 = time()
        print(f'\n[{func.__name__}] Execution time: {(t2-t1):.4f}s')
        return result
    return wrap_func


@timer
def encrypt(key, input_file, output_file, chunksize=64 * 1024):

    iv = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    filesize = os.path.getsize(input_file)

    with open(input_file, 'rb') as input:
        with open(output_file, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = input.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


@timer
def decrypt(key, input_file, output_file, chunksize=64 * 1024):
    with open(input_file, 'rb') as input:
        origsize = struct.unpack('<Q', input.read(struct.calcsize('Q')))[0]
        iv = input.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(output_file, 'wb') as outfile:
            while True:
                chunk = input.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


if __name__ == "__main__":
    encrypt(KEY, INPUT_PATH, OUTPUT_PATH)
    decrypt(KEY, OUTPUT_PATH, 'decrypted.txt')
