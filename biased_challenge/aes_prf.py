from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def int_to_bytes(x, size):
    return x.to_bytes(size, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

# output_length is in bytes
def aes_prf(key, t, output_length=16, input_length=16):
    t_bytes = t.to_bytes(input_length, 'big')

    # Pad the input data to make it a multiple of 16 bytes (AES block size)
    padded_data = pad(t_bytes, 16)

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt padded_data
    encrypted_bytes = cipher.encrypt(padded_data)

    # Convert encrypted_bytes to an integer
    encrypted_int = int.from_bytes(encrypted_bytes[:output_length], 'big')

    encrypted_int = encrypted_int % (2 ** (128))

    return encrypted_int
