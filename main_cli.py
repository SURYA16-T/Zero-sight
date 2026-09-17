#!/usr/bin/env python3
"""
ZeroSight CLI: Privacy-Preserving Eligibility Verification Engine.
Runs blind homomorphic evaluation and local cryptographic verification.
"""

import os
import sys
import argparse
import json
import time

from bee.config import DEFAULT_KEY_SIZE, FALLBACK_KEY_SIZE
from bee.parser import parse_file
from bee.extractor import extract_and_normalize_fields
from bee.validator import validate_extracted_data
from bee.policy import load_policy, compute_policy_hash
from bee.crypto_utils import (
    generate_keypair,
    encrypt_fields,
    decrypt_score,
    compute_public_key_fingerprint,
)
from bee.evaluator import evaluate_encrypted, evaluate_plaintext
from bee.comparison import compare_results
from bee.audit import generate_verification_receipt, format_receipt_as_markdown
from bee.serializer import serialize_public_key, serialize_encrypted_dict


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ZeroSight: Privacy-Preserving Homomorphic Eligibility Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file_path",
        help="Path to input document (.json, .txt, .pdf)",
    )
    parser.add_argument(
        "--policy",
        default="community_welfare_v1",
        help="Policy ID or path to policy JSON (default: community_welfare_v1)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_KEY_SIZE,
        choices=[1024, 2048],
        help=f"Paillier modulus bit length (default: {DEFAULT_KEY_SIZE} for NIST security)",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Display truncated ciphertexts and cryptographic telemetry",
    )
    parser.add_argument(
        "--receipt",
        metavar="OUT_FILE",
        help="Save cryptographic proof receipt to specified file",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not os.path.isfile(args.file_path):
        print(f"\033[91m[Error] File not found: {args.file_path}\033[0m")
        sys.exit(1)

    print("\033[1;36m" + "=" * 64)
    print("      ZEROSIGHT : PRIVACY-PRESERVING ELIGIBILITY ENGINE")
    print("=" * 64 + "\033[0m")

    # 1. Load Policy
    try:
        policy = load_policy(args.policy)
        print(f"[*] Loaded Policy: \033[1m{policy.get('title', policy.get('policy_id'))}\033[0m")
        print(f"[*] Policy SHA-256 Digest: \033[93m{policy['_hash'][:24]}...\033[0m")
        print(f"[*] Threshold: \033[92m{policy['threshold']}\033[0m")
    except Exception as e:
        print(f"\033[91m[Error] Failed to load policy: {e}\033[0m")
        sys.exit(1)

    # 2. Read and Parse Input Document
    ext = os.path.splitext(args.file_path)[1].lstrip(".")
    try:
        with open(args.file_path, "rb") as f:
            raw_content = f.read()

        print(f"[*] Reading and parsing '{args.file_path}' ({len(raw_content)} bytes)...")
        raw_parsed = parse_file(raw_content, ext)
        extracted = extract_and_normalize_fields(raw_parsed)
        print(f"[+] Extracted {len(extracted)} normalized fields: {list(extracted.keys())}")
    except Exception as e:
        print(f"\033[91m[Error] Parsing failed: {e}\033[0m")
        sys.exit(1)

    # 3. Validate Extracted Fields against Policy
    validation_errors = validate_extracted_data(extracted, policy)
    if validation_errors:
        print("\033[91m[!] Validation Errors:\033[0m")
        for err in validation_errors:
            print(f"    - {err}")
        sys.exit(1)
    print("[+] Validation passed successfully.")

    # 4. Generate Paillier Keypair Locally
    print(f"[*] Generating {args.key_size}-bit Paillier Keypair (entropy from OS CSPRNG)...")
    t0 = time.perf_counter()
    public_key, private_key = generate_keypair(key_size=args.key_size)
    t_keygen = time.perf_counter() - t0
    pub_fingerprint = compute_public_key_fingerprint(public_key)
    print(f"[+] Keypair generated in {t_keygen:.3f}s. Public Key Fingerprint: \033[94m{pub_fingerprint}\033[0m")

    # 5. Encrypt Selected Fields Locally
    print("[*] Encrypting sensitive fields with Paillier PHE...")
    t0 = time.perf_counter()
    encrypted_fields = encrypt_fields(public_key, extracted)
    t_enc = time.perf_counter() - t0
    print(f"[+] Encrypted {len(encrypted_fields)} fields in {t_enc:.3f}s.")

    if args.inspect:
        print("\n\033[90m--- Cryptographic Inspector (Ciphertext Previews) ---")
        for k, enc_num in encrypted_fields.items():
            ct_str = str(enc_num.ciphertext())
            print(f"  {k:15}: Enc({ct_str[:16]}...{ct_str[-16:]}) [len={len(ct_str)} digits]")
        print("-" * 52 + "\033[0m\n")

    # 6. Blind Evaluation (Zero Plaintext Knowledge)
    print("[*] Dispatching ciphertexts to Evaluator Engine (Zero Plaintext Sent)...")
    t0 = time.perf_counter()
    encrypted_score = evaluate_encrypted(public_key, encrypted_fields, policy)
    t_eval = time.perf_counter() - t0
    print(f"[+] Blind homomorphic evaluation computed in {t_eval:.3f}s.")

    # 7. Local Decryption of Evaluation Score
    print("[*] Decrypting evaluation score locally...")
    t0 = time.perf_counter()
    decrypted_score = decrypt_score(private_key, encrypted_score)
    t_dec = time.perf_counter() - t0
    print(f"[+] Decryption completed in {t_dec:.3f}s.")

    # 8. Local Plaintext Parity Verification (Demonstration Only)
    plaintext_score = evaluate_plaintext(extracted, policy)
    comparison = compare_results(plaintext_score, decrypted_score, policy)

    # 9. Render Final Result
    is_eligible = comparison["encrypted_result"] == "Eligible"
    res_color = "\033[1;92m" if is_eligible else "\033[1;91m"

    print("\n" + "=" * 64)
    print(f"  DETERMINATION: {res_color}{comparison['encrypted_result'].upper()}\033[0m")
    print("=" * 64)
    print(f"  * Homomorphic Decrypted Score : \033[1m{decrypted_score}\033[0m")
    print(f"  * Policy Threshold Required   : \033[1m{policy['threshold']}\033[0m")
    print(f"  * Plaintext Local Score       : \033[1m{plaintext_score}\033[0m")
    print(f"  * Parity Match Status         : \033[92m{comparison['match_status']}\033[0m")
    print("=" * 64)

    # 10. Generate Verifiable Proof Receipt
    receipt = generate_verification_receipt(
        policy=policy,
        public_key_fingerprint=pub_fingerprint,
        key_size=args.key_size,
        evaluated_fields=list(extracted.keys()),
        decrypted_score=decrypted_score,
        result=comparison["encrypted_result"],
        is_match=comparison["is_match"],
    )

    if args.receipt:
        out_ext = os.path.splitext(args.receipt)[1].lower()
        with open(args.receipt, "w", encoding="utf-8") as f:
            if out_ext == ".json":
                json.dump(receipt, f, indent=2)
            else:
                f.write(format_receipt_as_markdown(receipt))
        print(f"\n[+] Verifiable cryptographic receipt saved to: {args.receipt}")

    print("\n\033[32m[✓] ZeroSight evaluation completed securely.\033[0m\n")


if __name__ == "__main__":
    main()
