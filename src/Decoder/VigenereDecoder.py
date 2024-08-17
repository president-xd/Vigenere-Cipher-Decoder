import string
import itertools

def _exit():
    raise SystemExit('\nExiting...\n')

class Decoder:
    def __init__(self, cipher, key):
        """
        Initializes a Decoder instance for decryption.

        Args:
            cipher (str): Encrypted vigenere ciphertext.
            key (str): The decryption key.
        """
        self.cipher = cipher
        self.key = key

    def decode_char(self, char, key_char):
        alpha_start = 65 if char.isupper() else 97
        decrypted_ord = (ord(char) - ord(key_char)) % 26 + alpha_start
        return chr(decrypted_ord)

    def decode_cipher(self):
        key_cycle = itertools.cycle(self.key)
        decrypted_text = ""

        for char in self.cipher:
            if char.isalpha():
                key_char = next(key_cycle).upper() if char.isupper() else next(key_cycle).lower()
                decrypted_text += self.decode_char(char, key_char)
            else:
                decrypted_text += char

        return decrypted_text


class BruteForcer:
    def __init__(self, cipher, known_text):
        """
        Initializes a BruteForcer instance for decrypting the encoded 
        cipher using a known part of the plaintext / flag.

        Args:
            cipher (str): Encrypted vigenere ciphertext.
            known_text (str): A known part of the plaintext/flag.
        """
        self.cipher = cipher
        self.known_text = known_text
        self.brute_digit = 1

    def brute_force_decode(self):
        """
        Attempts to decrypt the cipher by bruteforcing and comparing
        with the known part / flag format.

        Returns:
            str: The decryption key if successful, else an empty string.
        """
        found_key = ""
        known_text2 = "".join(filter(str.isalpha, self.known_text))

        for index, digit in enumerate(known_text2):
            for potential_key in string.ascii_lowercase:
                test_key = found_key + potential_key
                decoded_text = Decoder("".join(filter(str.isalpha, self.cipher)), test_key).decode_cipher()

                if decoded_text[: index + 1] == known_text2[: index + 1]:
                    found_key += potential_key
                    decodeee = Decoder(self.cipher, found_key).decode_cipher()

                    if decodeee[: len(self.known_text)] == self.known_text:
                        return found_key

                    break
            else:
                print(f"No key found for digit: {digit}")
                break

        return found_key

    def bruteforce(self, key):
        """
        Attempts to find the decryption key through bruteforce.

        This method generates possible decryption keys and deciphers the
        cipher using each key until a match is found. It allows appending
        additional letters to the key.

        Args:
            key (str): The initial decryption key.
        """
        while True:
            print("")
            for x in itertools.product(string.ascii_lowercase, repeat=self.brute_digit):
                new_key = key + "".join(x)
                new_text = Decoder(self.cipher, new_key).decode_cipher()

                if new_text.startswith(self.known_text):
                    print(f"Key: {new_key} | Flag: {new_text}")
            try:
                try_again = input("Again Bruteforce? (y/n): ")
                if try_again.lower() == "n":
                    _exit()
                
                additional_letters = input(f"Append letter to key {key}: ")
                key += additional_letters
            except KeyboardInterrupt:
                _exit()


def main():
    print("Vigenère Cipher Decoder by President")

    cipher = input("Input Cipher Text: ")
    print("Enter (K) for Key")
    print("Enter (T) for Text")
    choice = input("Enter your choice: ").lower()
    
    if choice == 'k':
        key = input("Enter the decryption key: ")
        decoder = Decoder(cipher, key)
        print(f"Decrypted Text: {decoder.decode_cipher()}")
    elif choice == 't':
        known_text = input("Enter the known text/flag format: ")
        bruteForcer = BruteForcer(cipher, known_text)
        results = bruteForcer.brute_force_decode()
        print(f"Possible Key: {results}")
        decoder = Decoder(cipher, results)
        print(f"Possible Decrypted Text: {decoder.decode_cipher()}")
        
        try:
            inp_brute = input("Exit or Bruteforce further? (e/b): ")
            if inp_brute.lower() == "e":
                _exit()
            else:
                bruteForcer.bruteforce(results)
        except KeyboardInterrupt:
            _exit()
    else:
        print("Invalid choice. Exiting.")
        _exit()

if __name__ == "__main__":
    main()
