import os
import random
import json
import time
from dotenv import load_dotenv
from aes_prf import aes_prf

def hex_to_int(hex_str):
    hex_str = hex_str.replace(' ', '')
    return int(hex_str, 16)

def load_data(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

class HonestProver:
    def __init__(self, p, q, g, x, A):
        self.protocol = (p, q, g)
        self.secret_key = x
        self.public_key = A
        self.r = None

    def prover_commitment(self):
        p, q, g = self.protocol
        self.r = random.randint(1, q - 1)
        t = pow(g, self.r, p)
        return t
    
    def prover_response(self, c):
        p, q, _ = self.protocol
        z = (self.r - c * self.secret_key) % q
        return z
    
class SubvertedVerifier:
    def __init__(self, p, q, g, A, backdoor_key):
        self.protocol = (p, q, g)
        self.public_key = A
        self.c = None
        self.r_t = None
        self.bd_key = backdoor_key

    def challenge(self, t, commitment):
        p, q, _ = self.protocol

        if self.r_t is None:
            c = random.randint(1, pow(2, t) - 1)
        else:
            c = aes_prf(self.bd_key, self.r_t, 128 // 8, p.bit_length() // 8) # adjust to challenge size

        self.r_t = commitment
        self.c = c
        
        return c
    
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

        self.honest_prover = HonestProver(p, q, g, x, A)
        self.subverted_verifier = SubvertedVerifier(p, q, g, A, backdoor_key)

    def simulate(self):
        
        transcripts = []
        time_values = []

        for _ in range(self.num_rounds):
            t = self.honest_prover.prover_commitment()

            challenge_bits = 128 # number of bits in the challenge

            start_time = time.time()

            c = self.subverted_verifier.challenge(challenge_bits, t)

            total_time = time.time() - start_time
            time_values.append(total_time)

            z = self.honest_prover.prover_response(c)
            valid = self.subverted_verifier.validate(t, z)

            if not valid:
                print("Verification failed")
                return
            

            transcripts.append((t, c, z))
            
        return transcripts, time_values


    
def main():
    backdoor_key = os.urandom(32)  # Use a random 32-byte key as the backdoor key

    protocol = SchnorrIdentificationProtocol(backdoor_key)

    transcripts, time_values = protocol.simulate()



if __name__ == "__main__":
    main()