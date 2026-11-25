import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sutra_net.compliance.trusted_checkpoint import (
    generate_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)


@pytest.fixture
def keypair():
    return generate_keypair()


# --------------------------------------------------------- passphrase PEM


def test_unencrypted_roundtrip_restores_same_key(keypair):
    private_key, _ = keypair

    restored = load_private_key(serialize_private_key(private_key))

    assert (
        restored.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        == private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def test_passphrase_encrypted_roundtrip(keypair):
    private_key, _ = keypair
    passphrase = b"correct horse battery staple"

    pem = serialize_private_key(private_key, passphrase=passphrase)
    restored = load_private_key(pem, passphrase=passphrase)

    assert restored.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_encrypted_pem_hides_raw_key_material(keypair):
    private_key, _ = keypair
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encrypted_pem = serialize_private_key(private_key, passphrase=b"secret")

    assert raw not in encrypted_pem
    assert b"ENCRYPTED" in encrypted_pem


def test_encrypted_pem_requires_passphrase(keypair):
    private_key, _ = keypair
    pem = serialize_private_key(private_key, passphrase=b"secret")

    with pytest.raises(ValueError, match="Invalid or unsupported"):
        load_private_key(pem)


def test_wrong_passphrase_is_rejected(keypair):
    private_key, _ = keypair
    pem = serialize_private_key(private_key, passphrase=b"secret")

    with pytest.raises(ValueError, match="Invalid or unsupported"):
        load_private_key(pem, passphrase=b"wrong")


def test_empty_passphrase_rejected(keypair):
    private_key, _ = keypair

    with pytest.raises(ValueError, match="Passphrase"):
        serialize_private_key(private_key, passphrase=b"")


def test_str_passphrase_rejected(keypair):
    private_key, _ = keypair

    with pytest.raises(ValueError, match="Passphrase"):
        serialize_private_key(private_key, passphrase="secret")
    with pytest.raises(ValueError, match="Passphrase"):
        load_private_key(b"x", passphrase="secret")


# ------------------------------------------------------- normalized errors


@pytest.mark.parametrize(
    "garbage",
    [b"", b"not a pem at all", b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"],
)
def test_malformed_private_pem_normalized_to_value_error(garbage):
    with pytest.raises(ValueError, match="Invalid or unsupported private key"):
        load_private_key(garbage)


@pytest.mark.parametrize(
    "garbage",
    [b"", b"not a pem at all", b"-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n"],
)
def test_malformed_public_pem_normalized_to_value_error(garbage):
    with pytest.raises(ValueError, match="Invalid or unsupported public key"):
        load_public_key(garbage)


def test_non_bytes_pem_rejected(keypair):
    with pytest.raises(ValueError, match="must be bytes"):
        load_private_key("string pem")
    with pytest.raises(ValueError, match="must be bytes"):
        load_public_key("string pem")


def test_non_ed25519_private_key_rejected_on_load():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with pytest.raises(ValueError, match="Ed25519"):
        load_private_key(pem)


def test_non_ed25519_private_key_rejected_on_serialize():
    ec_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(ValueError, match="Ed25519"):
        serialize_private_key(ec_key)


def test_non_ed25519_public_key_rejected_on_serialize():
    ec_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(ValueError, match="Ed25519"):
        serialize_public_key(ec_key.public_key())


def test_bytearray_inputs_accepted(keypair):
    private_key, public_key = keypair

    restored = load_private_key(bytearray(serialize_private_key(private_key)))
    restored_public = load_public_key(bytearray(serialize_public_key(public_key)))

    assert restored is not None
    assert restored_public is not None
