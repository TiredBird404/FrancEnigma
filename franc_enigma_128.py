import secrets
import hashlib
import hmac

VERSION : bytes = b"FE128b"
BYTE_LEN : int = 16

class Cryption:
    def __init__(self, text : bytes, key : bytes) -> None:
        self.text : bytes = text
        self.key : bytes = key
        
    def encryption(self) -> bytes:
        salt : bytes = get_random_bytes()
        enigma_key, mac_key = self._generate_kdf_key(salt)

        self.text = Diffusion(self.text).diffuse()

        franc_enigma = FrancEnigma(enigma_key)
        encrypted : bytes = franc_enigma.cipher(self.text)

        mac : bytes = self._generate_mac(encrypted, mac_key)

        return salt + encrypted + mac

    def decryption(self) -> tuple[bytes, bool]:
        if len(self.text) < (BYTE_LEN * 2):
            return b'', False
        salt : bytes = self.text[:BYTE_LEN]
        mac : bytes = self.text[-BYTE_LEN:]
        encrypted : bytes = self.text[BYTE_LEN:-BYTE_LEN]

        enigma_key, mac_key = self._generate_kdf_key(salt)

        check_mac : bytes = self._generate_mac(encrypted, mac_key)
        
        if hmac.compare_digest(mac, check_mac) == False:
            return b'', False
        
        franc_enigma = FrancEnigma(enigma_key)
        decrypted : bytes = franc_enigma.cipher(encrypted)

        decrypted = Undiffusion(decrypted).undiffuse()

        return decrypted, True

    def _generate_kdf_key(self, salt : bytes) -> tuple[bytes, bytes]: # first for cryption, second for mac
        kdf_key : bytes = hashlib.pbkdf2_hmac("sha256", self.key + VERSION, salt, 10**6, BYTE_LEN * 2)
        return kdf_key[:BYTE_LEN], kdf_key[-BYTE_LEN:]
    
    def _generate_mac(self, text : bytes, key : bytes) -> bytes:
        hmac_result : bytes = hmac.new(
            key=key,
            msg=text,
            digestmod=hashlib.sha3_512
        ).digest()
        return hashlib.shake_256(hmac_result).digest(BYTE_LEN)

class FrancEnigma:
    def __init__(self, kdf_key : bytes) -> None:
        # generate rotors
        hash_random = HashRandom(kdf_key + b"rotors")
        new_rotor_list : list[bytearray] = []
        for _ in range(BYTE_LEN):
            new_rotor : bytearray = bytearray(range(256))
            for i in range(255, 0, -1): # use fisher-yates shuffle to get a new rotor
                l = hash_random.randbelow(i + 1)
                new_rotor[i], new_rotor[l] = new_rotor[l], new_rotor[i]
            new_rotor_list.append(new_rotor)
        self.rotors : list[bytearray] = new_rotor_list
        # other parameters
        self.deflect : list[int] = list(hashlib.shake_256(kdf_key + b"deflect").digest(BYTE_LEN))
        self.rotation_strength : int = hashlib.shake_128(kdf_key + b"strength").digest(1)[0]
        self.rotation_strength = self.rotation_strength // 2 * 2 + 1 # make the number to odd
    
    def cipher(self, text : bytes) -> bytes:
        rotors : list[bytearray] = self.rotors
        reversed_rotors : list[bytearray] = rotors[::-1]
        deflect : list[int] = self.deflect
        rotation_strength : int = self.rotation_strength

        deflect_len : int = len(deflect)

        result : bytearray = bytearray(text)

        for i, byte in enumerate(result):
            # pass rotors
            for r, d in zip(rotors, deflect):
                byte = r[(byte + d) % 256]
            for d in deflect:
                byte ^= d
            for r, d in zip(reversed_rotors, reversed(deflect)):
                byte = (r.index(byte) - d) % 256
            result[i] = byte

            # turn rotor
            deflect[0] += rotation_strength
            for n in range(deflect_len): # carry
                if deflect[n] >= 256:
                    deflect[n] %= 256
                    if n < (deflect_len - 1):
                        deflect[n + 1] += 1
                else:
                    break
        self.deflect = deflect
        return bytes(result)

class HashRandom:
    def __init__(self, seed : bytes) -> None:
        self.state : bytes = seed

    def randbelow(self, max_num : int) -> int:
        if max_num < 1: max_num = 1
        bit_len = (max_num - 1).bit_length()
        byte_needed: int = bit_len // 8 + 1
        mask = (1 << bit_len) - 1
        while True:
            self.state = hashlib.sha256(self.state).digest() # update state 
            raw_bytes: bytes = hashlib.shake_128(self.state).digest(byte_needed)
            value : int = int.from_bytes(raw_bytes, 'big')
            value &= mask
            if value < max_num:
                return value

class Diffusion:
    def __init__(self, text : bytes) -> None:
        self.text : bytearray = bytearray(text)
        self.text_len : int = len(self.text)
    
    def diffuse(self) -> bytes:
        for _ in range(16):
            self._change_place()
            self._add()
            self.text.reverse()
            self._xor()
        return bytes(self.text)
    
    def _change_place(self) -> None:
        self.text = self.text[1::2] + self.text[0::2]

    def _add(self) -> None:
        for i in range(self.text_len):
            self.text[i] = (self.text[i] + i + 1) % 256

    def _xor(self) -> None:
        for i in range(self.text_len - 1):
            self.text[i + 1] ^= self.text[i]

class Undiffusion:
    def __init__(self, text : bytes) -> None:
        self.text : bytearray = bytearray(text)
        self.text_len : int = len(self.text)
    
    def undiffuse(self) -> bytes:
        for _ in range(16):
            self._un_xor()
            self.text.reverse()
            self._reduce()
            self._upright()
        return bytes(self.text)

    def _upright(self) -> None:
        half_len : int = self.text_len // 2
        odd : bytearray = self.text[:half_len]
        even : bytearray = self.text[half_len:]
        self.text[0::2] = even
        self.text[1::2] = odd

    def _reduce(self) -> None:
        for i in range(self.text_len):
            self.text[i] = (self.text[i] - i - 1) % 256

    def _un_xor(self) -> None:
        for i in range(self.text_len - 1, 0, -1):
            self.text[i] ^= self.text[i - 1]

def get_random_bytes() -> bytes:
    return secrets.token_bytes(BYTE_LEN)
