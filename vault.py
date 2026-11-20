import base64
import hashlib
import hmac
import itertools
import json
import math
import os
import string
import time
import urllib.parse


ENVELOPE_PREFIX = "AEGISX1:"
COMMON_WEAK_PASSWORDS = {
    "123456", "password", "admin", "root", "toor", "qwerty",
    "12345678", "letmein", "pass123", "welcome", "123123", "abc123",
    "iloveyou", "monkey", "dragon", "shadow", "master", "654321"
}
COMMON_CIPHER_KEYS = [
    "key", "pass", "secret", "admin", "cipher", "token",
    "root", "kali", "aegis", "test", "lock", "node"
]
MORSE_TO_CHAR = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-....-": "-", "-.--.": "(", "-.--.-": ")"
}
CHAR_TO_MORSE = {v: k for k, v in MORSE_TO_CHAR.items()}


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _english_readability_score(text: str) -> float:
    if not text:
        return -999.0
    printable = sum(1 for c in text if c.isprintable())
    if printable / len(text) < 0.85:
        return -100.0
    common_tokens = ("the", "and", "to", "of", "is", "in", "for", "flag", "http", "admin", "user", "key", "note")
    lower = text.lower()
    score = sum(12.0 for tok in common_tokens if tok in lower)
    score += sum(2.0 for c in text if c in string.ascii_letters + string.digits + " _-:/.,!?@")
    return round(score, 2)


def _derive_keys(passphrase: str, salt: bytes, iterations: int = 120000) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations,
        dklen=64
    )
    return material[:32], material[32:]


def _keystream(enc_key: bytes, salt: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block_input = enc_key + salt + counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(block_input).digest())
        counter += 1
    return bytes(out[:length])


def _permute_block(block: bytes, round_key: int, reverse: bool = False) -> bytes:
    n = len(block)
    if n <= 1:
        return block
    indices = list(range(n))
    for i in range(n - 1, 0, -1):
        j = (round_key * 1315423911 + i * 2654435761) % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    result = bytearray(n)
    if not reverse:
        for idx, src_idx in enumerate(indices):
            result[idx] = block[src_idx]
    else:
        for idx, src_idx in enumerate(indices):
            result[src_idx] = block[idx]
    return bytes(result)


def _transform_blocks(data: bytes, enc_key: bytes, salt: bytes, decrypt: bool = False) -> bytes:
    block_size = 16
    ks = _keystream(enc_key, salt, len(data))
    xored = bytes(a ^ b for a, b in zip(data, ks))
    rounds = 6
    out = bytearray(len(xored))
    for offset in range(0, len(xored), block_size):
        chunk = xored[offset:offset + block_size]
        if not decrypt:
            cur = chunk
            for r in range(rounds):
                rk = enc_key[r % len(enc_key)] ^ salt[r % len(salt)] ^ (r + 1)
                cur = _permute_block(cur, rk, reverse=False)
                cur = bytes((b + rk + r) % 256 for b in cur)
            out[offset:offset + len(cur)] = cur
        else:
            cur = chunk
            for r in range(rounds - 1, -1, -1):
                rk = enc_key[r % len(enc_key)] ^ salt[r % len(salt)] ^ (r + 1)
                cur = bytes((b - rk - r) % 256 for b in cur)
                cur = _permute_block(cur, rk, reverse=True)
            out[offset:offset + len(cur)] = cur
    return bytes(out)


def wrap_payload(plaintext: str, passphrase: str) -> str:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    salt = os.urandom(16)
    enc_key, mac_key = _derive_keys(passphrase, salt)
    plain_bytes = plaintext.encode("utf-8")
    cipher_bytes = _transform_blocks(plain_bytes, enc_key, salt, decrypt=False)
    tag = hmac.new(mac_key, salt + cipher_bytes, hashlib.sha256).digest()
    payload_obj = {
        "alg": "AEGIS-X-v1",
        "s": base64.b64encode(salt).decode("ascii"),
        "c": base64.b64encode(cipher_bytes).decode("ascii"),
        "t": base64.b64encode(tag).decode("ascii")
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return ENVELOPE_PREFIX + encoded


def unwrap_payload(envelope: str, passphrase: str) -> str:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    token = envelope.strip()
    if not token.startswith(ENVELOPE_PREFIX):
        raise ValueError("Invalid AEGIS-X-v1 envelope prefix.")
    raw_b64 = token[len(ENVELOPE_PREFIX):]
    try:
        raw_json = base64.urlsafe_b64decode(raw_b64.encode("ascii")).decode("utf-8")
        obj = json.loads(raw_json)
        salt = base64.b64decode(obj["s"])
        cipher_bytes = base64.b64decode(obj["c"])
        tag = base64.b64decode(obj["t"])
    except Exception:
        raise ValueError("Malformed or corrupted AEGIS-X-v1 envelope.")
    enc_key, mac_key = _derive_keys(passphrase, salt)
    expected_tag = hmac.new(mac_key, salt + cipher_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Integrity check failed: wrong passphrase or tampered payload.")
    plain_bytes = _transform_blocks(cipher_bytes, enc_key, salt, decrypt=True)
    return plain_bytes.decode("utf-8")


def analyze_pattern(sample: str) -> dict:
    text = sample.strip()
    length = len(text)
    entropy = calculate_entropy(text)
    is_envelope = text.startswith(ENVELOPE_PREFIX)
    hex_chars = set(string.hexdigits)
    is_hex = length > 0 and length % 2 == 0 and all(c in hex_chars for c in text)
    b64_chars = set(string.ascii_letters + string.digits + "+/=-_")
    is_b64 = length >= 4 and all(c in b64_chars for c in text)
    alpha_only = length > 0 and all(c.isalpha() or c.isspace() for c in text)
    is_morse = length > 0 and all(c in ".-/ " for c in text) and ("." in text or "-" in text)

    if is_envelope:
        detected_type = "AEGIS-X-v1 Authenticated Envelope"
        confidence = "High"
    elif is_morse:
        detected_type = "Morse Code Signal"
        confidence = "Medium-High"
    elif is_hex and length >= 8:
        detected_type = "Hexadecimal Encoding"
        confidence = "Medium-High"
    elif is_b64 and ("=" in text or entropy > 4.2):
        detected_type = "Base64 / URL-Safe Encoding"
        confidence = "Medium"
    elif alpha_only:
        detected_type = "Alphabetic / Classical Substitution Candidate"
        confidence = "Low-Medium"
    else:
        detected_type = "Raw Text / Mixed Token"
        confidence = "Low"

    unique_ratio = round(len(set(text)) / length, 3) if length > 0 else 0.0

    return {
        "length": length,
        "entropy": entropy,
        "unique_char_ratio": unique_ratio,
        "detected_type": detected_type,
        "confidence": confidence,
        "is_aegis_envelope": is_envelope
    }


def audit_key_strength(passphrase: str) -> dict:
    findings = []
    score = 100
    if not passphrase:
        return {"score": 0, "rating": "Critical / Empty", "findings": ["No passphrase provided."]}
    if len(passphrase) < 8:
        score -= 35
        findings.append("Passphrase length is under 8 characters (high brute-force risk).")
    elif len(passphrase) < 12:
        score -= 15
        findings.append("Passphrase length is moderate; 12+ characters recommended.")
    if passphrase.lower() in COMMON_WEAK_PASSWORDS:
        score -= 50
        findings.append("Passphrase matches a common weak password list.")
    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_sym = any(not c.isalnum() for c in passphrase)
    variety = sum([has_upper, has_lower, has_digit, has_sym])
    if variety < 2:
        score -= 25
        findings.append("Low character diversity (mix uppercase, lowercase, digits, and symbols).")
    score = max(0, min(100, score))
    if score >= 80:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    else:
        rating = "Weak"
    if not findings:
        findings.append("Passphrase meets strong entropy and length criteria.")
    return {"score": score, "rating": rating, "findings": findings}


def detect_vulnerabilities(sample: str, passphrase: str = "") -> dict:
    pattern = analyze_pattern(sample)
    vulns = []

    if pattern["detected_type"] == "Hexadecimal Encoding":
        try:
            decoded = bytes.fromhex(sample.strip()).decode("utf-8", errors="replace")
            vulns.append({
                "id": "CRYPTO-VULN-01",
                "severity": "High",
                "title": "Encoding Used Instead of Encryption (Hex)",
                "detail": f"Input decodes directly without a key to: '{decoded[:80]}'",
                "remediation": "Wrap sensitive data with AEGIS-X-v1 (PBKDF2 + HMAC-SHA256) instead of Hex."
            })
        except Exception:
            pass

    if pattern["detected_type"] == "Base64 / URL-Safe Encoding":
        try:
            padded = sample.strip() + ("=" * ((4 - len(sample.strip()) % 4) % 4))
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
            if decoded.isprintable() and len(decoded.strip()) > 0:
                vulns.append({
                    "id": "CRYPTO-VULN-02",
                    "severity": "High",
                    "title": "Encoding Used Instead of Encryption (Base64)",
                    "detail": f"Base64 is reversible obfuscation, not encryption. Sample preview: '{decoded[:80]}'",
                    "remediation": "Use authenticated encryption (AEGIS-X-v1) with a strong secret passphrase."
                })
        except Exception:
            pass

    if pattern["detected_type"] == "Alphabetic / Classical Substitution Candidate":
        vulns.append({
            "id": "CRYPTO-VULN-03",
            "severity": "High",
            "title": "Susceptible to Classical Cipher / Frequency Analysis",
            "detail": "Pure alphabetic structure with low keyspace can be broken rapidly via shift/substitution analysis.",
            "remediation": "Replace classical ciphers with PBKDF2 key derivation and multi-round block mixing."
        })

    if not pattern["is_aegis_envelope"] and pattern["length"] > 0:
        vulns.append({
            "id": "CRYPTO-VULN-04",
            "severity": "Medium",
            "title": "Missing Integrity / Authentication Tag (HMAC)",
            "detail": "Input is not wrapped in an AEGIS-X-v1 envelope, so silent modification or bit-flipping is not detected.",
            "remediation": "Encapsulate output inside an AEGIS-X-v1 envelope to verify integrity via HMAC-SHA256."
        })

    if pattern["unique_char_ratio"] < 0.35 and pattern["length"] >= 10:
        vulns.append({
            "id": "CRYPTO-VULN-05",
            "severity": "Medium",
            "title": "High Character Repetition / Weak Diffusion",
            "detail": f"Low unique character ratio ({pattern['unique_char_ratio']}) indicates repetitive patterns.",
            "remediation": "Ensure proper salting and multi-round diffusion so small changes alter output broadly."
        })

    key_audit = None
    if passphrase:
        key_audit = audit_key_strength(passphrase)
        if key_audit["rating"] in ("Weak", "Critical / Empty"):
            vulns.append({
                "id": "CRYPTO-VULN-06",
                "severity": "High",
                "title": "Weak Passphrase / Key Material",
                "detail": " ; ".join(key_audit["findings"]),
                "remediation": "Use a high-entropy passphrase of at least 12 characters."
            })

    return {
        "pattern": pattern,
        "key_audit": key_audit,
        "vulnerability_count": len(vulns),
        "vulnerabilities": vulns
    }


def controlled_caesar_lab(ciphertext: str) -> dict:
    clean = ciphertext.strip()
    candidates = []
    for shift in range(26):
        shifted_chars = []
        for ch in clean:
            if "a" <= ch <= "z":
                shifted_chars.append(chr((ord(ch) - 97 - shift) % 26 + 97))
            elif "A" <= ch <= "Z":
                shifted_chars.append(chr((ord(ch) - 65 - shift) % 26 + 65))
            else:
                shifted_chars.append(ch)
        candidates.append({"shift": shift, "candidate": "".join(shifted_chars)})
    return {
        "total_keyspace_tested": 26,
        "status": "Broken exhaustively in 26 shifts (demonstrating weak keyspace)",
        "results": candidates[:10]
    }


def rot13_lab(text: str) -> dict:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return {"algorithm": "ROT13", "output": "".join(out)}


def morse_lab(sample: str) -> dict:
    clean = sample.strip()
    is_morse = all(c in ".-/ " for c in clean) and ("." in clean or "-" in clean)
    if is_morse:
        words = clean.split(" / ")
        decoded_words = []
        for w in words:
            chars = [MORSE_TO_CHAR.get(tok, "?") for tok in w.split() if tok]
            decoded_words.append("".join(chars))
        return {"direction": "morse_to_text", "output": " ".join(decoded_words)}
    encoded_tokens = []
    for ch in clean.upper():
        if ch == " ":
            encoded_tokens.append("/")
        elif ch in CHAR_TO_MORSE:
            encoded_tokens.append(CHAR_TO_MORSE[ch])
    return {"direction": "text_to_morse", "output": " ".join(encoded_tokens)}


def atbash_lab(text: str) -> dict:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(122 - (ord(ch) - 97)))
        elif "A" <= ch <= "Z":
            out.append(chr(90 - (ord(ch) - 65)))
        else:
            out.append(ch)
    return {"algorithm": "Atbash", "output": "".join(out)}


def _estimate_key_lengths(letters_only: str, max_len: int = 8) -> list[dict]:
    if len(letters_only) < 6:
        return []
    estimates = []
    for klen in range(2, min(max_len, len(letters_only) // 2) + 1):
        matches = 0
        comparisons = 0
        for i in range(len(letters_only) - klen):
            comparisons += 1
            if letters_only[i] == letters_only[i + klen]:
                matches += 1
        ratio = round(matches / comparisons, 4) if comparisons else 0.0
        estimates.append({"key_len": klen, "coincidence_ratio": ratio})
    estimates.sort(key=lambda x: x["coincidence_ratio"], reverse=True)
    return estimates[:4]


def vigenere_lab(ciphertext: str, max_attempts: int = 5000, timeout: float = 5.0) -> dict:
    start = time.perf_counter()
    attempts = 0
    scored = []
    letters = "".join(c.lower() for c in ciphertext if c.isalpha())
    key_len_hints = _estimate_key_lengths(letters)
    for key in COMMON_CIPHER_KEYS:
        if attempts >= max_attempts or (time.perf_counter() - start) >= timeout:
            break
        attempts += 1
        res = []
        ki = 0
        for ch in ciphertext:
            if "a" <= ch <= "z":
                shift = ord(key[ki % len(key)]) - 97
                res.append(chr((ord(ch) - 97 - shift) % 26 + 97))
                ki += 1
            elif "A" <= ch <= "Z":
                shift = ord(key[ki % len(key)]) - 97
                res.append(chr((ord(ch) - 65 - shift) % 26 + 65))
                ki += 1
            else:
                res.append(ch)
        cand = "".join(res)
        scored.append({"key": key, "score": _english_readability_score(cand), "candidate": cand})
    scored.sort(key=lambda x: x["score"], reverse=True)
    elapsed = round(time.perf_counter() - start, 4)
    return {
        "algorithm": "Vigenere (Key Length Hint + Dictionary Lab)",
        "key_length_hints": key_len_hints,
        "attempts": attempts,
        "elapsed_sec": elapsed,
        "top_candidates": scored[:5]
    }


def decode_layers_lab(sample: str, max_layers: int = 8) -> dict:
    cur = sample.strip()
    steps = []
    for layer in range(1, max_layers + 1):
        changed = False
        unquoted = urllib.parse.unquote(cur)
        if unquoted != cur and unquoted.isprintable():
            cur = unquoted
            steps.append({"layer": layer, "codec": "URL", "preview": cur[:100]})
            changed = True
            continue
        hex_chars = set(string.hexdigits)
        compact = cur.replace(" ", "")
        if len(compact) >= 4 and len(compact) % 2 == 0 and all(c in hex_chars for c in compact):
            try:
                dec = bytes.fromhex(compact).decode("utf-8")
                if dec.isprintable() and dec != cur:
                    cur = dec
                    steps.append({"layer": layer, "codec": "Hex", "preview": cur[:100]})
                    changed = True
                    continue
            except Exception:
                pass
        b64_chars = set(string.ascii_letters + string.digits + "+/=-_")
        if len(cur) >= 4 and all(c in b64_chars for c in cur):
            try:
                padded = cur + ("=" * ((4 - len(cur) % 4) % 4))
                dec = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
                if dec.isprintable() and dec != cur:
                    cur = dec
                    steps.append({"layer": layer, "codec": "Base64", "preview": cur[:100]})
                    changed = True
                    continue
            except Exception:
                pass
        if not changed:
            break
    return {
        "layers_peeled": len(steps),
        "final_output": cur,
        "steps": steps
    }


def xor_single_byte_lab(hex_or_text: str) -> dict:
    raw_str = hex_or_text.strip()
    hex_chars = set(string.hexdigits)
    if len(raw_str) >= 2 and len(raw_str) % 2 == 0 and all(c in hex_chars for c in raw_str):
        data = bytes.fromhex(raw_str)
        input_mode = "hex"
    else:
        data = raw_str.encode("utf-8", errors="replace")
        input_mode = "utf8"

    results = []
    for key in range(256):
        dec_bytes = bytes(b ^ key for b in data)
        dec_text = dec_bytes.decode("utf-8", errors="replace")
        results.append({
            "key_dec": key,
            "key_hex": f"0x{key:02x}",
            "score": _english_readability_score(dec_text),
            "candidate": dec_text[:90]
        })
    results.sort(key=lambda x: x["score"], reverse=True)
    return {
        "input_mode": input_mode,
        "keyspace_tested": 256,
        "top_candidates": results[:6]
    }


def xor_repeating_lab(hex_or_text: str, max_key_len: int = 3, max_attempts: int = 80000, timeout: float = 5.0) -> dict:
    raw_str = hex_or_text.strip()
    hex_chars = set(string.hexdigits)
    if len(raw_str) >= 2 and len(raw_str) % 2 == 0 and all(c in hex_chars for c in raw_str):
        data = bytes.fromhex(raw_str)
    else:
        data = raw_str.encode("utf-8", errors="replace")

    alphabet = string.ascii_lowercase.encode("ascii")
    start = time.perf_counter()
    attempts = 0
    best = []
    stopped_reason = "completed"

    for klen in range(2, max_key_len + 1):
        for tup in itertools.product(alphabet, repeat=klen):
            if attempts >= max_attempts:
                stopped_reason = "max_attempts_reached"
                break
            if (time.perf_counter() - start) >= timeout:
                stopped_reason = "timeout_reached"
                break
            attempts += 1
            dec_bytes = bytes(data[i] ^ tup[i % klen] for i in range(len(data)))
            dec_text = dec_bytes.decode("utf-8", errors="ignore")
            if dec_text:
                sc = _english_readability_score(dec_text)
                if sc > 18.0:
                    key_str = bytes(tup).decode("ascii")
                    best.append({"key": key_str, "score": sc, "candidate": dec_text[:80]})
        if stopped_reason != "completed":
            break

    best.sort(key=lambda x: x["score"], reverse=True)
    elapsed = max(0.0001, time.perf_counter() - start)
    return {
        "attempts": attempts,
        "elapsed_sec": round(elapsed, 4),
        "attempts_per_sec": int(attempts / elapsed),
        "stopped_reason": stopped_reason,
        "top_candidates": best[:6]
    }


def weak_hash_lab(target_hash: str, algo: str = "md5", max_attempts: int = 200000, timeout: float = 8.0) -> dict:
    h_clean = target_hash.strip().lower()
    algo_clean = algo.strip().lower()
    if algo_clean not in ("md5", "sha1", "sha256"):
        raise ValueError("Unsupported hash algorithm. Choose from: md5, sha1, sha256.")

    def _digest(word: str) -> str:
        return hashlib.new(algo_clean, word.encode("utf-8")).hexdigest()

    start = time.perf_counter()
    attempts = 0
    found = None
    stopped_reason = "exhausted_bounded_space"

    wordlist = list(COMMON_WEAK_PASSWORDS) + [str(i) for i in range(0, 10000)]
    for w in wordlist:
        if attempts >= max_attempts:
            stopped_reason = "max_attempts_reached"
            break
        if (time.perf_counter() - start) >= timeout:
            stopped_reason = "timeout_reached"
            break
        attempts += 1
        if _digest(w) == h_clean:
            found = w
            stopped_reason = "cracked"
            break

    if not found and stopped_reason not in ("max_attempts_reached", "timeout_reached"):
        chars = string.ascii_lowercase + string.digits
        for length in range(1, 5):
            for tup in itertools.product(chars, repeat=length):
                if attempts >= max_attempts:
                    stopped_reason = "max_attempts_reached"
                    break
                if (time.perf_counter() - start) >= timeout:
                    stopped_reason = "timeout_reached"
                    break
                attempts += 1
                cand = "".join(tup)
                if _digest(cand) == h_clean:
                    found = cand
                    stopped_reason = "cracked"
                    break
            if found or stopped_reason != "exhausted_bounded_space":
                break

    elapsed = max(0.0001, time.perf_counter() - start)
    return {
        "algorithm": algo_clean,
        "target_hash": h_clean,
        "cracked": found is not None,
        "match": found,
        "attempts": attempts,
        "elapsed_sec": round(elapsed, 4),
        "attempts_per_sec": int(attempts / elapsed),
        "stopped_reason": stopped_reason
    }


def compare_protection_lab(plaintext: str, passphrase: str) -> dict:
    b64_sample = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
    sealed = wrap_payload(plaintext, passphrase)
    return {
        "plaintext_len": len(plaintext),
        "encoding_only": {
            "format": "Base64",
            "entropy": calculate_entropy(b64_sample),
            "length": len(b64_sample),
            "integrity_protected": False
        },
        "authenticated_envelope": {
            "format": "AEGIS-X-v1 (PBKDF2-HMAC-SHA256 + Block Mix + HMAC)",
            "entropy": calculate_entropy(sealed),
            "length": len(sealed),
            "integrity_protected": True
        }
    }


def tamper_resistance_demo(plaintext: str, passphrase: str) -> dict:
    sealed = wrap_payload(plaintext, passphrase)
    prefix, body = sealed.split(":", 1)
    chars = list(body)
    mid = len(chars) // 2
    chars[mid] = "A" if chars[mid] != "A" else "B"
    tampered_envelope = f"{prefix}:{''.join(chars)}"

    tamper_blocked = False
    tamper_error = ""
    try:
        unwrap_payload(tampered_envelope, passphrase)
    except ValueError as exc:
        tamper_blocked = True
        tamper_error = str(exc)

    wrong_pass_blocked = False
    wrong_pass_error = ""
    try:
        unwrap_payload(sealed, passphrase + "_wrong")
    except ValueError as exc:
        wrong_pass_blocked = True
        wrong_pass_error = str(exc)

    return {
        "sealed_sample": sealed[:64] + "...",
        "tampered_envelope_blocked": tamper_blocked,
        "tamper_message": tamper_error,
        "wrong_passphrase_blocked": wrong_pass_blocked,
        "wrong_passphrase_message": wrong_pass_error
    }
