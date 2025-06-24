import itertools
import pikepdf
from tqdm import tqdm
import string
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def generate_passwords(chars, min_length, max_length):
    """Generator to yield passwords of given length using provided characters."""
    for length in range(min_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            yield ''.join(password)


def estimate_total_passwords(chars, min_length, max_length):
    """Estimates total number of passwords without generating them."""
    return sum(len(chars) ** length for length in range(min_length, max_length + 1))


def load_wordlist(wordlist_file):
    """Loads passwords from a wordlist file."""
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as file:
        return [line.strip() for line in file if line.strip()]


def try_password(pdf_file, password):
    """Attempts to open the PDF with the provided password."""
    try:
        with pikepdf.open(pdf_file, password=password):
            return password
    except pikepdf._core.PasswordError:
        return None


def decrypt_pdf(pdf_file, passwords, total_passwords, max_workers=4):
    """Attempts to decrypt PDF using multithreading and a list or generator of passwords."""
    with tqdm(total=total_passwords, desc='Decrypting PDF', unit='passwords') as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_password = {}
            try:
                for pwd in passwords:
                    future = executor.submit(try_password, pdf_file, pwd)
                    future_to_password[future] = pwd

                for future in as_completed(future_to_password):
                    pbar.update(1)
                    result = future.result()
                    if result:
                        pbar.n = total_passwords
                        pbar.refresh()
                        return result


            except KeyboardInterrupt:
                print("\n[!] Process interrupted by user.")
                return None

    print("[-] Unable to decrypt PDF. Password not found.")
    return None


def main():
    parser = argparse.ArgumentParser(description="Decrypt a password-protected PDF file.")
    parser.add_argument('pdf_file', help='Path to password-protected PDF file.')
    parser.add_argument('-w', '--wordlist', help='Path to the password list file.')
    parser.add_argument('-g', '--generate', action='store_true', help='Generate passwords on the fly.')
    parser.add_argument('-min', '--min_length', type=int, default=1, help='Minimum password length to generate.')
    parser.add_argument('-max', '--max_length', type=int, default=3, help='Maximum password length to generate.')
    parser.add_argument('-c', '--charset', type=str,
                        default=string.ascii_letters + string.digits + string.punctuation,
                        help='Characters to use for password generation.')
    parser.add_argument('--max_workers', type=int, default=6, help='Maximum number of parallel threads.')

    args = parser.parse_args()

    if not os.path.isfile(args.pdf_file):
        print("Error: PDF file not found.")
        return

    if args.generate:
        print("[*] Generating passwords...")
        passwords = generate_passwords(args.charset, args.min_length, args.max_length)
        total_passwords = estimate_total_passwords(args.charset, args.min_length, args.max_length)
    elif args.wordlist:
        if not os.path.isfile(args.wordlist):
            print("Error: Wordlist file not found.")
            return
        print("[*] Loading wordlist...")
        passwords = load_wordlist(args.wordlist)
        total_passwords = len(passwords)
    else:
        print("Error: Either --wordlist or --generate must be provided.")
        return

    print(f"[*] Total passwords to try: {total_passwords}")

    decrypted_password = decrypt_pdf(args.pdf_file, passwords, total_passwords, args.max_workers)

    if decrypted_password:
        print(f"[+] PDF decrypted successfully with password: {decrypted_password}")
    else:
        print("[-] Unable to decrypt PDF.")


if __name__ == '__main__':
    main()
