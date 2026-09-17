import pytest
from phe import paillier
from cryptography.exceptions import InvalidTag
from bee.key_management import export_encrypted_private_key, load_encrypted_private_key

def test_export_and_load_private_key():
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    passphrase = "super_secure_passphrase"
    
    blob = export_encrypted_private_key(private_key, passphrase)
    assert "salt" in blob
    assert "nonce" in blob
    assert "ciphertext" in blob
    assert blob["kdf"] == "argon2id"
    
    loaded_private_key = load_encrypted_private_key(blob, passphrase, public_key)
    
    assert loaded_private_key.p == private_key.p
    assert loaded_private_key.q == private_key.q

def test_load_private_key_wrong_passphrase():
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    passphrase = "super_secure_passphrase"
    wrong_passphrase = "wrong_secure_passphrase"
    
    blob = export_encrypted_private_key(private_key, passphrase)
    
    with pytest.raises(InvalidTag):
        load_encrypted_private_key(blob, wrong_passphrase, public_key)

def test_export_short_passphrase():
    public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
    
    with pytest.raises(ValueError, match="Passphrase must be at least 12 characters long"):
        export_encrypted_private_key(private_key, "short")
