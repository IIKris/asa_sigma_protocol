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
        self.bd_key = backdoor_key
        self.bit_number = bit_number

    def prover_commitment(self):
        p, q, g = self.protocol
        self.r = random.randint(1, q - 1)
        t = pow(g, self.r, p)

        # subverted commitment
        l, b = aes_prf(self.bd_key, t, self.secret_key.bit_length(), self.bit_number // 8)
        if self.x_bits[l] == b:
            return t, l
        
        self.r = random.randint(1, q - 1)
        t = pow(g, self.r, p)
        return t, l
    
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
        self.bit_number = int(os.getenv('BIT_NUMBER')) # type: ignore
        self.num_rounds = 0

        # load the json data
        data = load_data('primes.json')
        p = hex_to_int(data[f'bit_{self.bit_number}'])
        q = (p - 1) // 2
        g = data['generator']

        x = random.randint(1, q - 1)
        A = pow(g, x, p)
        self.params = (p, q, g)
        self.secret_key = x
        self.public_key = A

        self.bd_key = backdoor_key
        self.counter = 0

        self.subverted_prover = SubvertedProver(p, q, g, x, A, backdoor_key, self.bit_number)
        self.honest_verifier = HonestVerifier(p, q, g, A)

    def simulate(self):
        
        transcripts = []
        start_time = time.time()
        time_values = []

        # counter for each bit poisition of the secret key
        bit_counters = [0] * self.secret_key.bit_length()
        transcripts_per_bit = 19
        min_counter = 0
        min_counter_old = 0

        # while min(bit_counters) < transcripts_per_bit:
        while min_counter < transcripts_per_bit:
            self.num_rounds += 1
            start_time = time.time()

            t, l = self.subverted_prover.prover_commitment()

            challenge_bits = 128 # number of bits in the challenge
            c = self.honest_verifier.challenge(challenge_bits)
            z = self.subverted_prover.prover_response(c)
            valid = self.honest_verifier.validate(t, z)

            total_time = time.time() - start_time
            time_values.append(total_time)

            l, b = aes_prf(self.bd_key, t, self.secret_key.bit_length(), self.bit_number // 8)

            if not valid:
                print("Verification failed")
                return
            
            transcripts.append((t, c, z))
            bit_counters[l] += 1
            min_counter = min(bit_counters)
            if min_counter > min_counter_old:
                min_counter_old = min_counter

        print("Number of rounds: ", self.num_rounds)
        
        return transcripts, time_values
    
def main():
    backdoor_key = os.urandom(32)  # Use a random 32-byte key as the backdoor key

    protocol = SchnorrIdentificationProtocol(backdoor_key)
    adversary = Adversary(protocol, backdoor_key)

    transcripts, time_values = protocol.simulate()

    recovered_x = adversary.obtain_secret(transcripts)

    adversary.save_attack(transcripts, protocol, time_values)

    # compare how many bits are different
    original_bits = [int(bit) for bit in bin(protocol.secret_key)[2:]]
    recovered_bits = recovered_x
    
    # compare
    diff = 0
    for i in range(len(original_bits)):
        if original_bits[i] != recovered_bits[i]:
            diff += 1

    print("Number of different bits: ", diff)

    recovered_x = int("".join([str(bit) for bit in recovered_x]), 2)

    print("Recovered secret key:", recovered_x)

    recovered_x = adversary.obtain_secret(transcripts)
    print("Original secret key number:", protocol.secret_key)
    print("Original secret key bits:", [int(bit) for bit in bin(protocol.secret_key)[2:]])
    print("Recovered secret key bits:", recovered_x)

    recovered_x = recovered_x[:len([int(bit) for bit in bin(protocol.secret_key)[2:]])]
    recovered_x = recovered_x[-1:] + recovered_x[:-1]
    recovered_x = int("".join([str(bit) for bit in recovered_x]), 2)

    print("Recovered secret key number:", recovered_x)

if __name__ == "__main__":
    main()