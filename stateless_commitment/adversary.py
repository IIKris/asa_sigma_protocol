from collections import defaultdict
from types import SimpleNamespace
import os
from aes_prf import aes_prf
import numpy as np
import uuid
import base64

class Adversary:
    def __init__(self, protocol, backdoor_key):
        self.protocol = protocol
        self.backdoor_key = backdoor_key

    @classmethod
    def empty(cls):
        return cls(None, None)
    
    def set_protocol(self, protocol):
        self.protocol = SimpleNamespace(**protocol)

    def set_backdoor_key(self, backdoor_key):
        self.backdoor_key = backdoor_key

    def obtain_secret(self, transcripts):
        bit_counters = np.zeros(self.protocol.secret_key.bit_length(), dtype=int)

        p, q, g = self.protocol.params

        for transcript in transcripts:
            t, c, r = transcript

            l, b = aes_prf(self.backdoor_key, t, self.protocol.secret_key.bit_length(), p.bit_length() // 8)

            bit_counters[l] += (1 if b else -1)

        # Recover the secret key by selecting the majority vote for each bit position
        recovered_secret_key = [1 if count > 0 else 0 for count in bit_counters]

        return recovered_secret_key
    
    def obtain_secret_detailed(self, transcripts): 
        bit_counters = np.zeros(self.protocol.secret_key.bit_length(), dtype=int)
        transcript_counters = np.zeros(self.protocol.secret_key.bit_length(), dtype=int)

        p, q, g = self.protocol.params

        for transcript in transcripts:
            t, c, r = transcript

            l, b = aes_prf(self.backdoor_key, t, self.protocol.secret_key.bit_length(), p.bit_length() // 8)

            bit_counters[l] += (1 if b else -1)
            transcript_counters[l] += 1

        # Recover the secret key by selecting the majority vote for each bit position
        recovered_secret_key = [1 if count > 0 else 0 for count in bit_counters]

        return recovered_secret_key, bit_counters, transcript_counters
    
    def save_attack(self, transcripts, protocol, time_values):
        # create a folder called "transcripts_randomId", save the transcripts to a file called "transcripts.txt" and save the protocol to a file called "protocol.txt"
        
        # 1. create a folder called "transcripts_randomId" with random uuid with maxximum 8 characters
        randomId = str(uuid.uuid4())[:8]
        folderName = "transcripts_" + randomId
        os.mkdir(folderName)

        # for the protocol, save bit_number, p, q, g, x, y, backdoor_key, bit_number
        with open(folderName + "/protocol.txt", "w") as f:
            f.write("bit_number," + str(protocol.bit_number) + "\n")
            f.write("p," + str(protocol.params[0]) + "\n")
            f.write("q," + str(protocol.params[1]) + "\n")
            f.write("g," + str(protocol.params[2]) + "\n")
            f.write("x," + str(protocol.secret_key) + "\n")
            f.write("y," + str(protocol.public_key) + "\n")
            # f.write("bd_key," + str(protocol.bd_key) + "\n")
            f.write("bd_key," + base64.b64encode(protocol.bd_key).decode("utf-8") + "\n")

        with open(folderName + "/transcripts.txt", "w") as f:
            for transcript in transcripts:
                f.write(str(transcript) + "\n")

        with open(folderName + "/time.txt", "w") as f:
            for time_value in time_values:
                f.write(str(time_value) + "\n")

    def load_attack(self, folder):
        # 1. create an emtpy object in which to store the protocol parameters, transcripts and timevalues
        protocol = defaultdict()
        transcripts = []
        time_values = []

        protocol["params"] = [0, 0, 0]
        protocol["secret_key"] = 0
        protocol["public_key"] = 0

        # 2. load the protocol parameters from the file "protocol.txt" in the folder
        with open(folder + "/protocol.txt", "r") as f:
            for line in f:
                if "bd_key" in line:
                    protocol["bd_key"] = base64.b64decode(line.strip().split(",")[1])
                    continue
                if "p" in line:
                    protocol["params"][0] = int(line.strip().split(",")[1])
                    continue
                if "q" in line:
                    protocol["params"][1] = int(line.strip().split(",")[1])
                    continue
                if "g" in line:
                    protocol["params"][2] = int(line.strip().split(",")[1])
                    continue
                if "x" in line:
                    protocol["secret_key"] = int(line.strip().split(",")[1])
                    continue
                if "y" in line:
                    protocol["public_key"] = int(line.strip().split(",")[1])
                    continue
                line = line.strip().split(",")
                protocol[line[0]] = int(line[1])

        # 3. load the transcripts from the file "transcripts.txt" in the folder
        with open(folder + "/transcripts.txt", "r") as f:
            for line in f:
                # the lines contain a list of 3 values, which are separated by ", "
                # so remove the ( and ) and split by ", "
                transcript = line.strip()[1:-1].split(", ")
                # transcript = line.strip().split(", ")
                transcript = [int(x) for x in transcript]
                transcripts.append(transcript)

        # 4. load the time values from the file "time.txt" in the folder
        with open(folder + "/time.txt", "r") as f:
            for line in f:
                time_values.append(float(line.strip()))

        # 5. return the protocol parameters, transcripts and time values
        return protocol, transcripts, time_values
    
    def analyse_attack(self, protocol, transcripts, time_values):
        # print each parameter of the protocol loaded from the file
        print("bit_number:", protocol["bit_number"])
        print("p, q, g:", protocol["params"])
        print("x:", protocol["secret_key"])
        print("y:", protocol["public_key"])
        print("bd_key:", protocol["bd_key"])

        # print the first 5 transcripts loaded from the file
        print("transcripts:", transcripts[:5])

        # print the first 5 time values loaded from the file
        print("time_values:", time_values[:5])

    def determine_false_bits(self, recovered_secret_key):
        # original secret in bit array
        original_bits = [int(bit) for bit in bin(self.protocol.secret_key)[2:]]

        # recovered secret in bit array
        recovered_bits = recovered_secret_key

        # find all bit positions that are different
        different_bits = [i for i in range(len(original_bits)) if original_bits[i] != recovered_bits[i]]

        # if there are no different bits, return empty Array
        if len(different_bits) == 0:
            return []
        
        return different_bits
    
    def analyse_bit_counters(self, bit_counters, transcript_counters):
        # find all bit positions with a value of 0
        zero_bits = [i for i in range(len(bit_counters)) if bit_counters[i] == 0]

        # find all bit positions with a value of 1
        one_bits = [i for i in range(len(bit_counters)) if bit_counters[i] == 1]

        # find all bit positions with a value of -1
        minus_one_bits = [i for i in range(len(bit_counters)) if bit_counters[i] == -1]

        # find all bit positions with a value of 2
        two_bits = [i for i in range(len(bit_counters)) if bit_counters[i] == 2]

        # find all bit positions with a value of -2
        minus_two_bits = [i for i in range(len(bit_counters)) if bit_counters[i] == -2]

        # count the number of all bit positions for all values
        total_bit_sum = len(zero_bits) + len(one_bits) + len(minus_one_bits) + len(two_bits) + len(minus_two_bits)


        return zero_bits, one_bits, minus_one_bits, two_bits, minus_two_bits, total_bit_sum
    
    def analyse_transcript_counter(self, transcript_counters):
        # find the positions in the array with the 5 smallest different values (if values are equal, all are returned)
        smallest_values = np.argpartition(transcript_counters, 5)[:5]

        # for each position save the value and the number of times it occurs
        smallest_values = [(i, transcript_counters[i]) for i in smallest_values]

        return smallest_values

    
def main():
    # 1. create an adversary object
    adversary = Adversary.empty()

    # 2. load the protocol parameters, transcripts and time values from the folder "transcripts_randomId"
    protocol, transcripts, time_values = adversary.load_attack("run_1536_99")
    adversary.set_protocol(protocol)
    adversary.set_backdoor_key(protocol["bd_key"])

    # Get the detailed key info:
    recovered_secret_key, bit_counters, transcript_counters = adversary.obtain_secret_detailed(transcripts)

    # false bit positions
    false_bits = adversary.determine_false_bits(recovered_secret_key)
    print("false bits:", false_bits)

    # analyse the bit counters
    zero_bits, one_bits, minus_one_bits, two_bits, minus_two_bits, total_bit_sum = adversary.analyse_bit_counters(bit_counters, transcript_counters)
    print("zero bits:", zero_bits)
    print("one bits:", one_bits)
    print("minus one bits:", minus_one_bits)
    print("two bits:", two_bits)
    print("minus two bits:", minus_two_bits)
    print("total bit sum:", total_bit_sum)


    # analyse the transcript counters
    smallest_values = adversary.analyse_transcript_counter(transcript_counters)
    print("smallest values:", smallest_values)

    # 3. analyse the attack
    # adversary.analyse_attack(protocol, transcripts, time_values)

    # 4. obtain the secret key
    # secret_key = adversary.obtain_secret(transcripts)

    # 5. print the secret key
    # print("secret_key:", secret_key)

    # 6. save the attack to a folder called "transcripts_randomId"
    # adversary.save_attack(transcripts, protocol, time_values)

if __name__ == "__main__":
    main()
