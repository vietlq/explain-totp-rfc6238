import pytest
from example import get_hotp, DigestAlgo


@pytest.mark.parametrize(
    "secret_bytes,counter,digest_algo,expected",
    [
        (b"12345678901234567890", 0, DigestAlgo.SHA1, "755224"),
        (b"12345678901234567890", 1, DigestAlgo.SHA1, "287082"),
        (b"12345678901234567890", 2, DigestAlgo.SHA1, "359152"),
        (b"12345678901234567890", 3, DigestAlgo.SHA1, "969429"),
        (b"12345678901234567890", 4, DigestAlgo.SHA1, "338314"),
        (b"12345678901234567890", 5, DigestAlgo.SHA1, "254676"),
        (b"12345678901234567890", 6, DigestAlgo.SHA1, "287922"),
        (b"12345678901234567890", 7, DigestAlgo.SHA1, "162583"),
        (b"12345678901234567890", 8, DigestAlgo.SHA1, "399871"),
        (b"12345678901234567890", 9, DigestAlgo.SHA1, "520489"),
        (b"12345678901234567890", 30, DigestAlgo.SHA1, "026920"),
    ],
)
def test_get_hotp(secret_bytes, counter, digest_algo, expected):
    # Refer to https://tools.ietf.org/html/rfc4226
    actual = get_hotp(secret_bytes, counter, digest_algo)
    assert actual == expected
