import os
import random
import json
from dotenv import load_dotenv

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
    
class HonestVerifier:
    def __init__(self, p, q, g, A):
        self.protocol = (p, q, g)
        self.public_key = A
        self.c = None

    def challenge(self, t):
        p, _, _ = self.protocol
        self.c = random.randint(1, pow(2, t) - 1)
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
    
class SchnorrIdentificationProtocol3:
    def __init__(self):
        load_dotenv()
        bit_number = int(os.getenv('BIT_NUMBER')) # type: ignore

        # load the json data
        data = load_data('primes.json')
        p = hex_to_int(data[f'bit_{bit_number}'])
        q = (p - 1) // 2
        g = data['generator']

        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        self.params = (p, q, g)
        self.secret_key = x
        self.public_key = y

        self.honest_prover = HonestProver(p, q, g, x, y)
        self.honest_verifier = HonestVerifier(p, q, g, y)

    def simulate(self):
        t = self.honest_prover.prover_commitment()

        challenge_bits = 128 # number of bits for the challenge
        c = self.honest_verifier.challenge(challenge_bits)
        z = self.honest_prover.prover_response(c)

        self.honest_verifier.validate(t, z)

    
def main():
    protocol = SchnorrIdentificationProtocol3()

    protocol.simulate()

if __name__ == "__main__":
    main()
