import os
import random
import json
import time
from dotenv import load_dotenv
from aes_prf import aes_prf
from adversary import Adversary

def hex_to_int(hex_str):
    hex_str = hex_str.replace(' ', '')
    return int(hex_str, 16)

def load_data(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

class SubvertedProver:
    def __init__(self, p, q, g, x, A, backdoor_key, bit_number):
        self.protocol = (p, q, g)
        self.secret_key = x
        self.x_bits = [int(bit) for bit in bin(x)[2:]]
        self.public_key = A
        self.r = None
        self.r_t = None
        self.sigma = 0
        self.bd_key = backdoor_key
        self.bit_number = bit_number

    def calculate_r(self): 
        p, q, g = self.protocol

        if self.r_t is None:
            self.r = random.randint(1, q - 1)
        else:
            x_bit = self.x_bits[self.sigma % len(self.x_bits)]
            prf_output = aes_prf(self.bd_key, self.r_t, x_bit, self.bit_number // 8)
            self.r = prf_output % p
        self.sigma = (self.sigma + 1) % len(self.x_bits)

        return self.r

    def prover_commitment(self):
        p, q, g = self.protocol
        self.r = self.calculate_r()
        t = pow(g, self.r, p)
        self.r_t = t
        return t
    
    def prover_response(self, c):
        p, q, _ = self.protocol
        z = (self.r - c * self.secret_key) % q
        return z
    
class HonestVerifier:
    def __init__(self, p, q, g, A):
        self.protocol = (p, q, g)
        self.public_key = A
        self.c = None

    def challenge(self, bits):
        p, _, _ = self.protocol
        self.c = random.randint(1, pow(2, bits) - 1)
        return self.c
    
    def validate(self, t, z):
        # test if A is in range 1 - (p - 1)
        p, q, g = self.protocol
        if self.public_key < 1 or self.public_key > p - 1:
            return False
        
        # test if A ^ q = 1 mod p
        if pow(self.public_key, q, p) != 1:
            return False

        # test if t = g^z * A^c mod p
        left = t % p
        right = (pow(g, z, p) * pow(self.public_key, self.c, p)) % p
        return left == right
    
class SchnorrIdentificationProtocol:
    def __init__(self, backdoor_key):
        load_dotenv()
        bit_number = int(os.getenv('BIT_NUMBER')) # type: ignore
        self.num_rounds = bit_number + 1

        # load the json data
        data = load_data('primes.json')
        p = hex_to_int(data[f'bit_{bit_number}'])
        q = (p - 1) // 2
        g = data['generator']

        x = random.randint(1, q - 1)
        A = pow(g, x, p)
        self.params = (p, q, g)
        self.secret_key = x
        self.public_key = A

        self.bd_key = backdoor_key
        self.counter = 0

        self.subverted_prover = SubvertedProver(p, q, g, x, A, backdoor_key, bit_number)
        self.honest_verifier = HonestVerifier(p, q, g, A)

    def simulate(self):
        
        transcripts = []
        time_values = []

        for _ in range(self.num_rounds):
            start_time = time.time()

            t = self.subverted_prover.prover_commitment()

            total_time = time.time() - start_time

            challenge_bits = 128 # number of bits in the challenge
            c = self.honest_verifier.challenge(challenge_bits)
            z = self.subverted_prover.prover_response(c)
            valid = self.honest_verifier.validate(t, z)

            total_time = time.time() - start_time
            time_values.append(total_time)

            if not valid:
                print("Verification failed")
                return

            transcripts.append((t, c, z))

        return transcripts, time_values


    
def main():
    backdoor_key = os.urandom(32)  # Use a random 32-byte key as the backdoor key

    protocol = SchnorrIdentificationProtocol(backdoor_key)
    adversary = Adversary(protocol, backdoor_key)

    start_time = time.time()

    transcripts, time_values = protocol.simulate()

    recovered_x = adversary.obtain_secret(transcripts)
    print("Original secret key number:", protocol.secret_key)
    print("Original secret key bits:", [int(bit) for bit in bin(protocol.secret_key)[2:]])
    print("Recovered secret key bits:", recovered_x)

    # trim the recovered key to the length of [int(bit) for bit in bin(protocol.secret_key)[2:]]
    recovered_x = recovered_x[:len([int(bit) for bit in bin(protocol.secret_key)[2:]])]

    recovered_x = recovered_x[-1:] + recovered_x[:-1]
    recovered_x = int("".join([str(bit) for bit in recovered_x]), 2)


    print("Recovered secret key number:", recovered_x)

    print("Time: ", time.time() - start_time)

if __name__ == "__main__":
    main()