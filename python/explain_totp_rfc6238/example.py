import hmac
import hashlib
import struct
from binascii import hexlify, unhexlify
from enum import Enum


class DigestAlgo(Enum):
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


DIGEST_ALGO_MAP = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def get_hotp_impl(secret_bytes: bytes, counter: int, make_digest_fn, digits: int = 6) -> int:
    if digits < 5 and digits > 9:
        raise ValueError(f"Expected number of digits: 5-9. Actual: {digits}")

    hmac_obj = hmac.new(secret_bytes, digestmod=make_digest_fn)

    # The HOTP values generated by the HOTP generator are treated as big endian.
    counter_raw = struct.pack(">Q", counter)

    hmac_obj.update(counter_raw)

    digest_res = hmac_obj.digest()
    offset = digest_res[-1] % 16
    truncated = digest_res[offset : offset + 4]
    last_31bits = int(hexlify(truncated), 16) & 0x7FFFFFFF

    htop_value = last_31bits % 10 ** digits
    return htop_value


def get_hotp(secret_bytes: bytes, counter: int, digest_algo: DigestAlgo, digits: int = 6) -> str:
    make_digest_fn = DIGEST_ALGO_MAP[digest_algo.value]
    htop_value = get_hotp_impl(secret_bytes, counter, make_digest_fn, digits)
    return f"{htop_value:0{digits}d}"


def get_totp_impl():
    pass


def get_totp():
    pass


if __name__ == "__main__":
    secret_bytes = b"12345678901234567890"

    for counter in range(10):
        print(
            f"The HTOP value of the counter {counter} with 6 digits: {get_hotp(secret_bytes, counter, DigestAlgo.SHA1)}"
        )

    for counter in range(10):
        value = get_hotp(secret_bytes, counter, DigestAlgo.SHA1, digits=7)
        print(f"The HTOP value of the counter {counter} with 7 digits: {value}")
