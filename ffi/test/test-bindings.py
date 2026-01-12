import base64
import ctypes
import json
import sys
import textwrap


def load_ffi_library(path):
    lib = ctypes.CDLL(path)

    lib.get_error.argtypes = [ctypes.c_void_p]
    lib.get_error.restype = ctypes.c_uint8

    lib.get_token.argtypes = [ctypes.c_void_p]
    lib.get_token.restype = ctypes.c_char_p

    lib.free_dpop_access_token.argtypes = [ctypes.c_void_p]
    lib.free_dpop_access_token.restype = None

    lib.generate_dpop_access_token.argtypes = [
        ctypes.c_char_p,  # dpop_proof
        ctypes.c_char_p,  # user
        ctypes.c_uint64,  # client_id
        ctypes.c_char_p,  # handle
        ctypes.c_char_p,  # display_name
        ctypes.c_char_p,  # team
        ctypes.c_char_p,  # domain
        ctypes.c_char_p,  # backend_nonce
        ctypes.c_char_p,  # uri
        ctypes.c_char_p,  # method
        ctypes.c_uint16,  # max_skew_secs
        ctypes.c_uint64,  # max_expiration
        ctypes.c_char_p,  # backend_keys
    ]
    lib.generate_dpop_access_token.restype = ctypes.c_void_p
    return lib


def sample_args():
    return dict(
        proof=b"eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLUE2T3ZqNFVzRmFrbFZMUHZhZDhYNF80MXRBTW55ZnR3aGVXbnNSMzVvbyIsInkiOiI3S3E3UzQxUjh4NUVzTnVjY1J4Y3ItcjN2SWhYVmloR3BLUFAweThIczBvIn19.eyJpYXQiOjE3MjcyMTI5NDIsImV4cCI6MjA0MjU3NjU0MiwibmJmIjoxNzI3MjEyOTQyLCJzdWIiOiJ3aXJlYXBwOi8vU3ZQZkxsd0JRaS02b2RkVlJya3FwdyE0YzdAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYS9hY21lL3dpcmUvY2hhbGxlbmdlL2FhYS9iYmIiLCJqdGkiOiJlNzg1MGYxNy1jYzc3LTQ0ZmYtYThiNi0wODMyYjA1NTdkNmUiLCJub25jZSI6IldFODhFdk9CemJxR2Vyem5NKzJQL0FhZFZmNzM3NHkwY0gxOXNEU1pBMkEiLCJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly93aXJlLmV4YW1wbGUuY29tL2NsaWVudC90b2tlbiIsImNoYWwiOiJva0FKMzNZbS9YUzJxbW1oaGg3YVdTYkJsWXk0VHRtMUV5c3FXOEkvOW5nIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGpvaG5fZG9lQGV4YW1wbGUuY29tIiwidGVhbSI6IjZlODVlMDUzLTUzNmYtNDU4NS04ZmM4LWNhZGE4NzZlNWVjNyIsIm5hbWUiOiJKb2huIERvZSJ9.M7Zc0FIHazWbWg6PeFK1DVJoLiLeqx09Y9KQSLPgrp5DzGnvj2Gxo4z0ELwzpIUv9pfuw4f-tImRQSS7_RKmww",
        user_id=b"4af3df2e-5c01-422f-baa1-d75546b92aa7",
        client_id=1223,
        handle=b"john_doe",
        display_name=b"John Doe",
        team=b"6e85e053-536f-4585-8fc8-cada876e5ec7",
        domain=b"example.com",
        backend_nonce=b"WE88EvOBzbqGerznM+2P/AadVf7374y0cH19sDSZA2A",
        uri=b"https://wire.example.com/client/token",
        method=b"POST",
        max_skew_secs=1,
        max_expiration=2042742401,
        backend_keys=textwrap.dedent("""
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5i88D4XpjBudqAkS
        3r4zMK0hEXT7i+xR3PyGfrPHcqahRANCAAQ84mdGFohHioIhOG/s8S2mHNXiKzdV
        ZTvpq663q4ErPGj7OP0P7Ef1QrXvHmTDOTx5YwUJ3OAxDXDOdSkD0zPt
        -----END PRIVATE KEY-----
        """).encode("utf-8"),
    )


def generate_token(lib, args):
    return lib.generate_dpop_access_token(
        args["proof"],
        args["user_id"],
        args["client_id"],
        args["handle"],
        args["display_name"],
        args["team"],
        args["domain"],
        args["backend_nonce"],
        args["uri"],
        args["method"],
        args["max_skew_secs"],
        args["max_expiration"],
        args["backend_keys"],
    )


def test_should_return_a_valid_access_token(lib):
    args = sample_args()
    result = generate_token(lib, args)
    assert lib.get_error(result) == 0
    token = lib.get_token(result)

    # do a simple header check, to make sure that the return value is a token,
    # which must be serialized using JWS Compact Serialization:
    # https://datatracker.ietf.org/doc/html/rfc7515#section-3.1
    header = token.split(b".")[0]
    # due to the use of base64url encoding, we need to add missing padding
    header += b"=" * (-len(header) % 4)
    header = json.loads(base64.urlsafe_b64decode(header))
    assert header["alg"] == "ES256"
    assert header["typ"] == "at+jwt"

    lib.free_dpop_access_token(result)


def test_should_return_an_error_when_given_wrong_nonce(lib):
    args = sample_args()
    args["backend_nonce"] = b"foobar"
    result = generate_token(lib, args)
    # error code 9 means that `backend_nonce` does not correspond to
    # the `nonce` claim in the DPoP token (base64url encoded)
    assert lib.get_error(result) == 9

    token = lib.get_token(result)
    assert token is None

    lib.free_dpop_access_token(result)


if __name__ == "__main__":
    assert len(sys.argv) == 2
    lib = load_ffi_library(sys.argv[1])

    test_should_return_a_valid_access_token(lib)
    test_should_return_an_error_when_given_wrong_nonce(lib)
