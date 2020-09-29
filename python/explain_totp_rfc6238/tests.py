import pytest
from example import get_hotp, DigestAlgo, get_totp_impl


SECRET_KEY_20 = b"12345678901234567890"
SECRET_KEY_32 = b"12345678901234567890123456789012"
SECRET_KEY_64 = b"1234567890123456789012345678901234567890123456789012345678901234"


@pytest.mark.parametrize(
    "unix_time,secret_bytes,digest_algo,digits,expected",
    [
        (59, SECRET_KEY_20, DigestAlgo.SHA1, 8, "94287082"),
        (59, SECRET_KEY_32, DigestAlgo.SHA256, 8, "46119246"),
        (59, SECRET_KEY_64, DigestAlgo.SHA512, 8, "90693936"),
        (1111111109, SECRET_KEY_20, DigestAlgo.SHA1, 8, "07081804"),
        (1111111109, SECRET_KEY_32, DigestAlgo.SHA256, 8, "68084774"),
        (1111111109, SECRET_KEY_64, DigestAlgo.SHA512, 8, "25091201",),
        (1111111111, SECRET_KEY_20, DigestAlgo.SHA1, 8, "14050471"),
        (1111111111, SECRET_KEY_32, DigestAlgo.SHA256, 8, "67062674"),
        (1111111111, SECRET_KEY_64, DigestAlgo.SHA512, 8, "99943326",),
        (1234567890, SECRET_KEY_20, DigestAlgo.SHA1, 8, "89005924"),
        (1234567890, SECRET_KEY_32, DigestAlgo.SHA256, 8, "91819424"),
        (1234567890, SECRET_KEY_64, DigestAlgo.SHA512, 8, "93441116",),
        (2000000000, SECRET_KEY_20, DigestAlgo.SHA1, 8, "69279037"),
        (2000000000, SECRET_KEY_32, DigestAlgo.SHA256, 8, "90698825"),
        (2000000000, SECRET_KEY_64, DigestAlgo.SHA512, 8, "38618901",),
        (20000000000, SECRET_KEY_20, DigestAlgo.SHA1, 8, "65353130"),
        (20000000000, SECRET_KEY_32, DigestAlgo.SHA256, 8, "77737706"),
        (20000000000, SECRET_KEY_64, DigestAlgo.SHA512, 8, "47863826",),
    ],
)
def test_get_totp_impl(unix_time, secret_bytes, digest_algo, digits, expected):
    # Refer to https://tools.ietf.org/html/rfc6238
    actual = get_totp_impl(unix_time=unix_time, secret_bytes=secret_bytes, digest_algo=digest_algo, digits=digits)
    assert actual == expected


@pytest.mark.parametrize(
    "secret_bytes,counter,digest_algo,expected",
    [
        (SECRET_KEY_20, 0, DigestAlgo.SHA1, "755224"),
        (SECRET_KEY_20, 1, DigestAlgo.SHA1, "287082"),
        (SECRET_KEY_20, 2, DigestAlgo.SHA1, "359152"),
        (SECRET_KEY_20, 3, DigestAlgo.SHA1, "969429"),
        (SECRET_KEY_20, 4, DigestAlgo.SHA1, "338314"),
        (SECRET_KEY_20, 5, DigestAlgo.SHA1, "254676"),
        (SECRET_KEY_20, 6, DigestAlgo.SHA1, "287922"),
        (SECRET_KEY_20, 7, DigestAlgo.SHA1, "162583"),
        (SECRET_KEY_20, 8, DigestAlgo.SHA1, "399871"),
        (SECRET_KEY_20, 9, DigestAlgo.SHA1, "520489"),
        (SECRET_KEY_20, 30, DigestAlgo.SHA1, "026920"),
    ],
)
def test_get_hotp(secret_bytes, counter, digest_algo, expected):
    # Refer to https://tools.ietf.org/html/rfc4226
    actual = get_hotp(secret_bytes=secret_bytes, counter=counter, digest_algo=digest_algo)
    assert actual == expected
