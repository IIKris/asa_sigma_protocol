from aes_prf import aes_prf

class Adversary:
    def __init__(self, protocol, backdoor_key):
        self.protocol = protocol
        self.backdoor_key = backdoor_key

    def obtain_secret(self, transcripts):
        # Access protocol parameters
        p, q, g = self.protocol.params

        # collection of x_bits
        x_bits = []

        # store the r_t value (the t value of the last transcript)
        r_t = None

        for transcript in transcripts:
            t, c, r = transcript

            # first transcript
            if r_t is None:
                r_t = t
            else:
                # try both possible values of x (0 and 1)
                for x_bit in [0, 1]:
                    # calculate the t value for the given x_bit
                    t_candidate = aes_prf(self.backdoor_key, r_t, x_bit, p.bit_length() // 8)
                    
                    # if calculated t value matches the collected t value
                    if pow(g, t_candidate % p, p) == t:
                        x_bits.append(x_bit)
                        r_t = t
                        break

        # secret_key = int(''.join(map(str, x_bits)), 2)
        secret_key = x_bits

        return secret_key
    