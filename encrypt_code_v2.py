#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
ADVANCED ENCRYPTOR + EMBED KEY + SELF-DECRYPT
================================================================================

Usage:
-----------
Example:
    python super_advanced_encryptor.py \
        -i source_file.py \
        -o output_encrypted.py
Or:
    python super_advanced_encryptor.py --inplace -i file_source.py

Dependencies:
-------------
- pycryptodome
- colorlog (opsional)
- pyfiglet (opsional, jika mau banner ascii)
- python 3.7+ (untuk concurrency modern, dsb.)

Author:
-------
- HikiNarou
- https://github.com/HikiNarou

"""

import sys
import os
import argparse
import logging
import traceback
import concurrent.futures
import base64
import getpass
import random
import string
import importlib.util

# --- OPTIONAL colorlog (for color in console logging) ---
try:
    import colorlog
    COLORLOG_AVAILABLE = True
except ImportError:
    COLORLOG_AVAILABLE = False

# --- OPTIONAL pyfiglet (for ascii banner) ---
try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

################################################################################
# GLOBAL CONSTANTS & DEFAULTS
################################################################################

# Marker
MARKER_START = "# ENCRYPT_START"
MARKER_END = "# ENCRYPT_END"

# Default embedded key (hard-coded).  <--- This is where the password is embedded.
# Later the output file will put HIDDEN_KEY = (this value).
EMBEDDED_KEY = "MY-SUPER-SECRET-KEY"

# Environment variable name for override key. 
# Just an example, to add “complexity”.
ENV_KEY_NAME = "OS_ENCRYPT_KEY"

# Length of ciphertext chunk per line in the output file (for neatness).
CIPHERTEXT_LINE_LENGTH = 64

# ANY OTHER TEXT IN INDONESIAN JUST USE MACHINE TRANSLATION TO YOUR LOCAL LANGUAGE.

################################################################################
# ADVANCED LOGGING SETUP
################################################################################

def setup_advanced_logging(log_level=logging.DEBUG, log_file="encryptor.log"):
    """
    Menyiapkan logger global dengan console handler + file handler.
    Jika colorlog terinstall, pakai format berwarna di console.
    """
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Format log standar
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")

    # File handler
    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setLevel(log_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console handler (bisa pakai colorlog kalau ada)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
    if COLORLOG_AVAILABLE:
        cformat = ("%(log_color)s[%(asctime)s] %(levelname)s - "
                   "%(reset)s%(message)s")
        cformatter = colorlog.ColoredFormatter(cformat, datefmt="%H:%M:%S")
        ch.setFormatter(cformatter)
    else:
        ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.debug("Advanced logging is set up.")
    return logger

################################################################################
# BANNER PRINT (OPSIONAL)
################################################################################

def print_banner():
    """
    Mencetak banner ASCII (jika pyfiglet tersedia). 
    Ini hanya hiasan, boleh di-skip.
    """
    if PYFIGLET_AVAILABLE:
        ascii_banner = pyfiglet.figlet_format("SUPER ADVANCED ENCRYPTOR")
        print(ascii_banner)
    else:
        print("=== SUPER ADVANCED ENCRYPTOR ===")

################################################################################
# ENCRYPTION STRATEGY
################################################################################

class EncryptionStrategyAESGCM:
    """
    Strategi enkripsi AES-256 GCM (dari pycryptodome).
    Mengembalikan dictionary header, salt, nonce, tag, ciphertext (semua base64).
    """
    def __init__(self, iterations=100000):
        self.iterations = iterations

    def encrypt(self, plain_text: str, password: str) -> dict:
        """
        Enkripsi plain_text dengan password.
        """
        data = plain_text.encode("utf-8")
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=self.iterations)
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return {
            "header": "ENCv1",
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

################################################################################
# CORE ENCRYPTION PROCESS
################################################################################

def process_file(
    input_path: str,
    output_path: str,
    password: str,
    iterations: int = 100000,
    log_on: bool = True
):
    """
    Membaca file input baris demi baris (secara paralel, walau overkill),
    mencari blok # ENCRYPT_START ... # ENCRYPT_END, 
    mengenkripsi isinya, lalu menuliskan file output dengan snippet self-decrypt.

    :param input_path:  Path file sumber
    :param output_path: Path file hasil
    :param password:    Password/kunci enkripsi
    :param iterations:  Iter PBKDF2
    :param log_on:      Jika True, logging.debug
    """
    if log_on:
        logging.debug("Reading input file lines (with concurrency, for no real reason).")

    # Baca baris-baris dengan concurrency (overkill).  
    # Sebenarnya sequential pun cukup, tapi ini agar "super advanced."
    with open(input_path, "r", encoding="utf-8") as fin:
        lines = fin.readlines()

    # Kita tidak benar-benar butuh concurrency di sini, 
    # tapi mari kita buat contoh konyol:
    def identity(line):
        return line
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futs = [executor.submit(identity, ln) for ln in lines]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())

    # results seharusnya sama persis dengan lines, 
    # urutannya mungkin beda, jadi kita re-assign lines= ...
    # Agar tetap sama urutan, sebenarnya kita butuh map, 
    # tapi ini contoh "random concurrency" saja. 
    # Di sini kita tak peduli perubahan urutan => just "show complexity."
    lines = results

    # Sort lines back to original if you care about order:
    # (We'll skip that just to illustrate how messy concurrency can be if not used carefully.)
    # In real usage, you'd keep track of indices. 
    # But let's do a naive approach: lines stays in random order => 
    # That would break code! 
    # We'll do a fallback: let's just read it normally again. 
    # This is purely comedic, to show "advanced" concurrency. 
    # We'll do the correct approach: use the results in order. 
    # Actually let's do something simpler: 
    # We'll just revert to the original lines we read in, ignoring concurrency. 
    lines = fin = None  # This is comedic sabotage, but let's fix it:
    with open(input_path, "r", encoding="utf-8") as fin:
        lines = fin.readlines()

    # Oke, concurrency di atas jadi tak berguna, haha. 
    # Let's keep going.

    # Sekarang kita lakukan enkripsi block
    strategy = EncryptionStrategyAESGCM(iterations=iterations)

    output_lines = []
    in_block = False
    block_lines = []
    current_indent = ""

    if log_on:
        logging.debug("Scanning lines for ENCRYPT_START ... ENCRYPT_END markers.")

    for line in lines:
        stripped = line.strip()
        if stripped == MARKER_START:
            in_block = True
            # Tangkap indentasi
            current_indent = line[:len(line) - len(line.lstrip())]
            output_lines.append(line)
            block_lines = []
            continue
        elif stripped == MARKER_END and in_block:
            in_block = False
            # Enkripsi block
            block_content = "".join(block_lines)
            enc_dict = strategy.encrypt(block_content, password)

            # Buat dictionary terenkripsi
            encrypted_block = (
                f"{current_indent}encrypted_code_dict = {{\n"
                f"{current_indent}    'header': '{enc_dict['header']}',\n"
                f"{current_indent}    'salt': '{enc_dict['salt']}',\n"
                f"{current_indent}    'nonce': '{enc_dict['nonce']}',\n"
                f"{current_indent}    'tag': '{enc_dict['tag']}',\n"
                f"{current_indent}    'ciphertext': '{enc_dict['ciphertext']}'\n"
                f"{current_indent}}}\n"
            )

            # Sisipkan key (hard-coded)
            hidden_key_line = f"{current_indent}HIDDEN_KEY = '{password}'\n"

            # Sisipkan snippet dekripsi otomatis (tanpa prompt)
            # Notice: Kami tulis advanced snippet agar kelihatan ribet.
            decrypt_snippet = f"""{current_indent}import base64
{current_indent}from Crypto.Cipher import AES
{current_indent}from Crypto.Protocol.KDF import PBKDF2

{current_indent}def _auto_decrypt_code(encrypted_dict, hidden_key, iterations={iterations}):
{current_indent}    \"\"\"
{current_indent}    Mendekripsi ciphertext berbasis AES GCM. 
{current_indent}    hidden_key disematkan di code, jadi user tidak perlu mengetik password.
{current_indent}    \"\"\"
{current_indent}    salt = base64.b64decode(encrypted_dict['salt'])
{current_indent}    nonce = base64.b64decode(encrypted_dict['nonce'])
{current_indent}    tag = base64.b64decode(encrypted_dict['tag'])
{current_indent}    ciphertext = base64.b64decode(encrypted_dict['ciphertext'])
{current_indent}    key = PBKDF2(hidden_key, salt, dkLen=32, count={iterations})
{current_indent}    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
{current_indent}    plain = cipher.decrypt_and_verify(ciphertext, tag)
{current_indent}    return plain.decode('utf-8')

{current_indent}decrypted_code = _auto_decrypt_code(encrypted_code_dict, HIDDEN_KEY)
{current_indent}exec(decrypted_code, globals(), locals())
"""

            output_lines.append(encrypted_block)
            output_lines.append(hidden_key_line)
            output_lines.append(decrypt_snippet)
            output_lines.append(line)  # Tulis "# ENCRYPT_END"
            continue

        if in_block:
            block_lines.append(line)
        else:
            output_lines.append(line)

    # Tulis ke file output
    if log_on:
        logging.debug("Writing to output file: %s", output_path)

    with open(output_path, "w", encoding="utf-8") as fout:
        fout.writelines(output_lines)

    if log_on:
        logging.debug("Encryption + embed key + self-decrypt snippet done.")

################################################################################
# MAIN CLI HANDLER
################################################################################

def main():
    """
    Fungsi utama: parse argumen, jalankan logic.
    """
    setup_advanced_logging(logging.DEBUG)
    print_banner()

    parser = argparse.ArgumentParser(
        description="Super advanced script to encrypt code blocks with embedded key + self-decrypt snippet."
    )

    # Subparsers - walau kita hanya punya satu subcommand, 
    # kita buat saja agar "nampak advanced."
    subparsers = parser.add_subparsers(dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt code blocks.")
    encrypt_parser.add_argument("-i", "--input", required=True, help="Path file input .py")
    encrypt_parser.add_argument("-o", "--output", help="Path file output .py")
    encrypt_parser.add_argument("--inplace", action="store_true", help="Overwrite file input.")
    encrypt_parser.add_argument("-n", "--iterations", type=int, default=100000,
                                help="Jumlah iterasi untuk PBKDF2 (default: 100000).")

    # Jika user tidak mengetik subcommand, kita asumsikan "encrypt" agar lebih ringkas
    args = parser.parse_args()
    if not args.command:
        # inject command="encrypt"
        args.command = "encrypt"

    if args.command == "encrypt":
        input_file = args.input
        if not os.path.exists(input_file):
            logging.error("File input %s tidak ditemukan.", input_file)
            sys.exit(1)

        # Menentukan output file
        if args.inplace:
            output_file = input_file
        else:
            if args.output:
                output_file = args.output
            else:
                logging.error("Harus tentukan -o/--output atau --inplace.")
                sys.exit(1)

        # Validasi ekstensi
        ext_in = os.path.splitext(input_file)[1]
        ext_out = os.path.splitext(output_file)[1]
        if ext_in.lower() != ext_out.lower():
            logging.error("Ekstensi file input (%s) dan output (%s) harus sama.",
                          ext_in, ext_out)
            sys.exit(1)

        # Password = cek environment override
        embedded_password = os.getenv(ENV_KEY_NAME, EMBEDDED_KEY)
        # Note: jika ada environment OS_ENCRYPT_KEY, kita pakai itu. 
        # else fallback ke EMBEDDED_KEY.

        try:
            process_file(
                input_path=input_file,
                output_path=output_file,
                password=embedded_password,
                iterations=args.iterations,
                log_on=True
            )
            logging.info("Proses enkripsi + embed key sukses. Hasil => %s", output_file)
        except Exception as e:
            logging.error("Terjadi error saat proses enkripsi: %s", e)
            logging.debug(traceback.format_exc())
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(0)

################################################################################
# ENTRY POINT
################################################################################

if __name__ == "__main__":
    main()
