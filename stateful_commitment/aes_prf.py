from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def int_to_bytes(x, size):
    return x.to_bytes(size, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

# output_length is in bytes
def aes_prf(key, r_t, x_bit, output_length=16):
    # Convert r_t to bytes
    r_t_bytes = r_t.to_bytes(output_length, 'big')

    # XOR the x_bit with the last byte of r_t_bytes
    r_t_bytes = bytearray(r_t_bytes)
    r_t_bytes[-1] ^= x_bit

    # Pad the input data to make it a multiple of 16 bytes (AES block size)
    padded_data = pad(bytes(r_t_bytes), 16)

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))

    # Encrypt padded_data
    encrypted_bytes = cipher.encrypt(padded_data)

    # Convert encrypted_bytes to an integer
    encrypted_int = int.from_bytes(encrypted_bytes[:output_length], 'big')

    return encrypted_int
