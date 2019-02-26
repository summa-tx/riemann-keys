from riemann_keys.hdkey import HDKey

# Mnemonic to root
MNEMONIC = "keen speed ice always runway film setup sentence update stove distance merge"
root_seed = HDKey.root_seed_from_mnemonic(mnemonic=MNEMONIC)
root = HDKey.from_root_seed(root_seed=root_seed)

print("public key " + root.public_key.hex())
print("private key " + root.private_key.hex())
print("chaincode " + root.chain_code.hex())
print("xpub " + root.extended_public_key)
print("xpriv " + root.extended_private_key)
print("\n")

# Derive to a node at depth of 5
node = root.derive_path("m/44'/1'/1'/0/1")
print("public key " + node.public_key.hex())
print("private key " + node.private_key.hex())
print("chaincode " + node.chain_code.hex())
print("xpub " + node.extended_public_key)
print("xpriv " + node.extended_private_key)
