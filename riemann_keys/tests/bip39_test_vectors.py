# flake8: noqa
#  https://github.com/trezor/python-mnemonic/blob/master/vectors.json
trezor_vectors = {
  "english": [
    {
      "id": 0,
      "entropy": "00000000000000000000000000000000",
      "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "salt": "TREZOR",
      "binary": "00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 00000000000 0000000",
      "checksum": "0011",
      "seed": "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
      "root": {
        "private_key": "cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184",
        "public_key": "02f632717d78bf73e74aa8461e2e782532abae4eed5110241025afb59ebfd3d2fd",
        "xpub": "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy",
        "xpriv": "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
        "parent_fingerprint": "00",
        "fingerprint": "b4e3f5ed",
        "depth": 0,
        "index": 0,
        "chain_code": "a3fa8c983223306de0f0f65e74ebb1e98aba751633bf91d5fb56529aa5c132c1"
      },
      "derived_node": {
        "path": "m/7'/13'/8'/65'/6/44/16/18'/7",
        "public_key": "026381791f9bf7ec99538a408d61c911737a30488c78004feb34a73295776c2f17",
        "private_key": "b4749323ef65b3898c8cf3f9978fa437c9113a3a91b26320a1047032ab9eaf47",
        "xpub": "xpub6Qo94BJ44WgahcCbte4pYt2UU5AGBrkt4PyKWzG3KA9AR1EbERqbTo69Wtc4cXnB2DiuFcxwEDRNdQh1GXwF1jqHrwZS3KRS6X7eaceREJd",
        "xpriv": "xprvABonefmAE98HV888ncXpBk5jv3KmnQ32hB3iibrRkpcBYCuSgtXLuzmffeBwvMLcouHL2WdJEZiiXJDB6cMDKytYPy37Em7BNCytyBhJd5A",
        "parent_fingerprint": "fc4ca6e2",
        "fingerprint": "264f90ed",
        "depth": 9,
        "index": 7,
        "chain_code": "3c063c0a452d20fba1b1cc476a886def7096116dd0cb8400d90f6f55507bcca6"
      }
    }
  ]
}

# generated with: https://iancoleman.io/bip39/#english
test_vectors = {
  "english": [
    {
      "id": 0,
      "entropy": "a4e3fc4c0161698a22707cfbf30f7f83",
      "mnemonic": "pilot cable basic actress bird shallow mean auto winner observe that all",
      "salt": None,
      "binary": "10100100111 00011111111 00010011000 00000010110 00010110100 11000101000 10001001110 00001111100 11111011111 10011000011 11011111111 0000011",
      "checksum": "0011",
      "seed": "af44c7ad86ba0a5f46d4c1e785c846db14e0f3d62b69c2ab7efa012a9c9155c024975d6897e36fe9e9e6f0bde55fdf325ff308914ed1b316da0f755f9dd7347d",
      "root": {
        "private_key": "c6796958d07afe0af1ba9a11da2b7a22d6226b4ff7ff5324c7c876cfc1ea0f1c",
        "public_key": "029cfe11e5f33a2601083ff5e29d9b7f134f5edc6b7636674a7286ecf6d23804df",
        "xpub": "xpub661MyMwAqRbcFXwuU8c1uEfmER2GW8A7XfaR9Cw41RCGr1xmr4WaLdU9cGPvcJXaaNYLFuu9bMimhKmGgaFja9BxcBAo98Eim1UuUu1dXAn",
        "xpriv": "xprv9s21ZrQH143K33sSN751Y6j2gPBn6fSGASepLpXST5fHyDddJXCKnq9fm1gRmHk4CPPcEF9gBmJvPBf74ExYM6Ybe6zwA7HfX8dQkRFY9S4",
        "parent_fingerprint": "00",
        "fingerprint": "f3ac0f3f",
        "depth": 0,
        "index": 0,
        "chain_code": "6399431d3f454a4acbe0f1cbb2d9a392a43dbea34e7fea952bdda675adde6e6e"
      },
      "derived_node": {
        "path": "m/55'/16'/34'/20/19'/97/21'/88'",
        "public_key": "039b8a22c4fb43cb4b52596fc2050357dd9771950d6b6881c6e4b2e78e1943f51d",
        "private_key": "258dc521c0581a788a2f08fd64be0f4d29c0c7384031960e6b6986526bcb039f",
        "xpub": "xpub6NjKMZDHrzmR8m4poa48Xzj3qeS32QQBbfXffSK5N4F6SLE35fFrBT9qECJ77LMic44hNnWTR86qVjE8r4DsMSNVztB1vyoYNvhzrg91zXV",
        "xpriv": "xprvA9jxx3gQ2dD7vGzMhYX8ArnKHcbYcwgLESc4s3uToii7ZXttY7wbdeqMNtRdhhepm7cEKKparnDqeigAPgj7KTj7Gw5ZGUKCRBYbkd3sdGo",
        "parent_fingerprint": "e33b22ce",
        "fingerprint": "93195471",
        "depth": 8,
        "index": 2147483736,
        "chain_code": "18eb1b59d8a529c9fdbfbce7f6cb03cc9b1bd80b2fc5abee1944b32a32c136f8"
      }
    },
    {
      "id": 1,
      "entropy": "8cfc94f3846c43fa893b4950155de2369772c91e",
      "mnemonic": "mind tool diagram angle service wool ceiling hard exotic priority joy honey jaguar goose kit",
      "salt": None,
      "binary": "10001100111 11100100101 00111100111 00001000110 11000100001 11111101010 00100100111 01101001001 01010000000 10101010111 01111000100 01101101001 01110111001 01100100100 011110",
      "checksum": "10111",
      "seed": "82555df2fd8c76fca417c83fc7ed0552a0310299eed41d3a45cf49e1ac056e21126e64d988052b9dbc0e04bd6b3580c51ab6a4ec5a62c5dba2039bd372e7d137",
      "root": {
        "private_key": "9fee59092ebbedc782277cf75bc85f9db0ea559818eb20de865c4897eb2144f4",
        "public_key": "0357ffdd29d20d72d2061c154353835b9cd34016d6f63755a04d70a7033e2919b3",
        "xpub": "xpub661MyMwAqRbcFyPp6zb6ZPcsuqVkvUm2Y61Gn7cRrkp2xxCD8ot9tgJQDKG6R6DWopMQrVoUhMChoCZcS4PKSFFx5AoNPAGFizikrRVTmpn",
        "xpriv": "xprv9s21ZrQH143K3VKLzy46CFg9MofGX23BAs5fyjCpJRH469s4bGZuLsyvN2qGCAYoJYmHyT6XVVkhm7DHGyHSyYPintmfgxYrwKHzCgCthir",
        "parent_fingerprint": "00",
        "fingerprint": "94db54c0",
        "depth": 0,
        "index": 0,
        "chain_code": "8faa80cab7372c9e12e2f54a445e434b5d2cb310bc92d7e304b914360a89278a"
      },
      "derived_node": {
        "path": "m/96'/2'/10/81'/60'/90'",
        "public_key": "0229d3838c6703a16aa9e7f8604dd308f36980ca891783f9e46dcc8d0a7c7da5ed",
        "private_key": "6f7ae238af855eb9e0cee63333a4c05ef4c24a54a6951dcdf298ea13c85e2050",
        "xpub": "xpub6JuoVny9rzjMruCwjgP66H9bLt97ow3jgg6Sjt5Eny85LQKoQzA6E9xhmFcVoQR2PoYnTTDMcXnyo1MZPHeW4PFBxaN6VitafnfA3csorkr",
        "xpriv": "xprvA5vT6HSG2dB4eR8Uder5j9CrnrJdQUKtKTAqwVfdEdb6TbzesSqqgMeDv17Qa6M5jxRcbhDTTfzzBxuJqMURrsXnRXNJUwkRsqNmTHEs6Qx",
        "parent_fingerprint": "db9f3893",
        "fingerprint": "11b20e3d",
        "depth": 6,
        "index": 2147483738,
        "chain_code": "91f4c0395a78095692132cb1f632834ab821c373057ccdb5637f7f9f34837fdd"
      }
    },
    {
      "id": 2,
      "entropy": "15bf57143a38579300d9f4cbd65adaebe01398fbeb8f44f0",
      "mnemonic": "between wide shallow inner lyrics sister address direct slim ready repeat style abuse small use impose eager liberty",
      "salt": None,
      "binary": "00010101101 11111010101 11000101000 01110100011 10000101011 11001001100 00000011011 00111110100 11001011110 10110010110 10110110101 11010111110 00000001001 11001100011 11101111101 01110001111 01000100111 10000",
      "checksum": "000111",
      "seed": "db6b9728bce174c1c14976415cfe06d63509e127f38ba265cf672315b5ed15953828f0fe5e9922654c07d3284f7ac11f814b564e87f94210d3bcc153ec6f698b",
      "root": {
        "private_key": "3a4014ab104dc69ba3820e3c1e9740998dfdd0b912f1f83268c639bac5fa64f0",
        "public_key": "03230ac7166adf9664a911a4d4785a60e79e983f950b99fe9dc228dd1438c0aa36",
        "xpub": "xpub661MyMwAqRbcFtZZGjnmsUKVffkBYUraocCexn2maSi1keXzdsaam5fwHRrwFaLNe1dCjqQQMgcGSQfaiD5BFuDbvy3cdkWrq3939hHHns9",
        "xpriv": "xprv9s21ZrQH143K3QV6AiFmWLNm7duh928jSPH4APdA27B2srCr6LGLDHMTS94eTRRBfnoLErXZEXbkAHpybohWnb4tp8sv3cSK7nJKtpcwJ4U",
        "parent_fingerprint": "00",
        "fingerprint": "b46fe1d0",
        "depth": 0,
        "index": 0,
        "chain_code": "874c576e48fdc3ebf6f0822b4d18498d0a545d6684dfd683ef215fd0273870e8"
      },
      "derived_node": {
        "path": "m/87/19/76/25'/96'",
        "public_key": "03540f45d9145cd5c9bdbf67b674df050255ac19380b0b6f3cc57dff99e17b836a",
        "private_key": "c3c055a5154dafa361e82d585393d82a8bf3f82cbe96f7c4e2e758de7ac90a0e",
        "xpub": "xpub6FwAvDCcTWuqD2hVZHoi3WhtWZbf2XBeo36HRFwCLLk85DxzvHau5dmx8o7VKsdrv98yigghdX6PkgeGvoe4LZ39Hoex2ZhGtJ53W4Tdnmn",
        "xpriv": "xprvA2wpWhfid9MXzYd2TGGhgNm9xXmAd4ToRpAgcsXan1D9CRdrNkGeXqTUHWzAimdLSuZCMCqMhu545mtYP4mj13q5RWDbuyBHBbwMeaPcAyU",
        "parent_fingerprint": "46ae4850",
        "fingerprint": "94d1cc4b",
        "depth": 5,
        "index": 2147483744,
        "chain_code": "309cff07ed70166ebe30ec31ee7a4c261fa9dfa6bdae249d498a84f4d224d472"
      }
    },
    {
      "id": 3,
      "entropy": "a05a7afb69e2cd81c838a7d1ad4132d06bef59042b0388512881b61a",
      "mnemonic": "park stable salute stable coast science can belt spider head erosion patch same prosper awful gather marriage matter call history pluck",
      "salt": None,
      "binary": "10100000010 11010011110 10111110110 11010011110 00101100110 11000000111 00100000111 00010100111 11010001101 01101010000 01001100101 10100000110 10111110111 10101100100 00010000101 01100000011 10001000010 10001001010 00100000011 01101100001 1010",
      "checksum": "0110101",
      "seed": "1929655fd266457fc620dd471f424b8351999338c837db07ec362dab19f11dbb2c2aff18d0a063a9d91239f81181d0fcebe327c37803b45012a8163fe3b716b6",
      "root": {
        "private_key": "a01b94f79e8c29ee63b8c27e40ef63f1cfe8f4cac870d0de5d20e889b1d8a13a",
        "public_key": "031225fa5e457da949ab1021931887131c7a53c06df0fce4d6a3dd5819aa5776e0",
        "xpub": "xpub661MyMwAqRbcFJsyHbfuQsjnh3qjSfXkxkEXa5JHoSbyU7UNoiXU3FXfcKUbdFqC5cyxexpUAYPZP6K9AU9C4FjfuiX743buQgF5k7BwUND",
        "xpriv": "xprv9s21ZrQH143K2poWBa8u3jo4921F3CoubXJvmgtgF74zbK9EGBDDVTDBm3acAnd1cvowkj1pvi7PK3Ab6XrwYfJPWmQtCp5kor3tbqkreJ6",
        "parent_fingerprint": "00",
        "fingerprint": "056dd4ec",
        "depth": 0,
        "index": 0,
        "chain_code": "4cf7eb64f359de9cdb7f2c05baf3267a2f1f96e1fc68333c60e92ff3dbbf0b78"
      },
      "derived_node": {
        "path": "m/85'/15/76",
        "public_key": "02029099fda4c09fa365c85cf785fb790270125bc0d9a584e1707ca2d85209eab2",
        "private_key": "921255b836b8215d67d18949b217f3b3edf77cc0d185d37ff85da85d6ca0657e",
        "xpub": "xpub6CnpKCiJ2WSFtjfzoreA69jdgCrLK2vVrzEhvJHHEDjREWLU2SYKwVkMVML9Gt22pMY2aa4RdEXedECPgyoegRy76vaPNpj8QzFwAxeRKmn",
        "xpriv": "xprv9yoTuhBQC8sxgFbXhq79j1nu8B1quaCeVmK77usfftCSMi1KUuE5PhRse7PaX8uh8stKfMGjNGN6ZiXVXBL54daSjmLvEe57u3m8mbGvHGv",
        "parent_fingerprint": "9aedbb6f",
        "fingerprint": "6ad6b30a",
        "depth": 3,
        "index": 76,
        "chain_code": "ec33efe03c9ad429a6e2cba47cdbc396ae2bded480c628f760396794e6f52729"
      }
    },
    {
      "id": 4,
      "entropy": "39281ecca67d16aa629115340d8ad4923bd49ec2d6f17669fce458087ee89a92",
      "mnemonic": "decrease domain rebel erupt sphere festival medal cargo cross hobby release caught run exhaust area taste island exit decorate quote margin inmate heart frog",
      "salt": None,
      "binary": "00111001001 01000000111 10110011001 01001100111 11010001011 01010101001 10001010010 00100010101 00110100000 01101100010 10110101001 00100100011 10111101010 01001111011 00001011010 11011110001 01110110011 01001111111 00111001000 10110000000 10000111111 01110100010 01101010010 010",
      "checksum": "11101001",
      "seed": "c11b0ff978d88c0ae9f7c349733bbd1b7baf2237663e3064a4c62bc4f5a578e4fb14fc43c38f85bfe83a15790397d7a301df5233d7d520cd2cc974cd33ae47b2",
      "root": {
        "private_key": "36f0fcac8ff8e73506ae26aa1db732918e0db5c5635330eaed951e12eacedf3e",
        "public_key": "02800f0237e39dce74f506c508985d4d71f8020342d7dfe781ca5cfb73e63eb43e",
        "xpub": "xpub661MyMwAqRbcGYp55aa3wf9WqTuPGdFnwyhFBALErewiMiBkeDrXsZ6qDbUbawSiHVgqvqobbNdosLY7aJgsNVv4DtwPAWKEjgCaSEjvdBg",
        "xpriv": "xprv9s21ZrQH143K44jbyZ33aXCnHS4tsAXwakmeNmvdJKQjUurc6gYHKknMNKtdTiC7jPbnEBmTWDEJ4HpxobatUpEKQgrshDpv8R1NrCkdWyT",
        "parent_fingerprint": "00",
        "fingerprint": "ea6be3d5",
        "depth": 0,
        "index": 0,
        "chain_code": "c989c416cf4c4e3d3708c25893ab6c01bcb9893e153929ab9204eb374ab76a63"
      },
      "derived_node": {
        "path": "m/51'",
        "public_key": "028f08404abc652f3170f471591cab170f153a0772adf69d33116212f9219537cc",
        "private_key": "e74f8cedbafd94797fd0d21ecb06ccac46721602ccb8a0fe86cdb54335d03691",
        "xpub": "xpub69cS8waJoeNVm5qKbGi2eyspJLHgP1zyZWgFJt2knTHGUhF45C8tthWzJ5cJTKQA77UvXkKvpdGh49ewZhDyQD2vFcSyTz3qjvstaxjPd4F",
        "xpriv": "xprv9vd5jS3QyGpCYbkrVFB2Hqw5kJTByZH8CHkeWVd9E7kHbtuuXepeLuCWSqFQy8o3iwPrPyw5trAwCpW9HvecxQkCNBeHUHmXiAu9mUWDviW",
        "parent_fingerprint": "ea6be3d5",
        "fingerprint": "97f01095",
        "depth": 1,
        "index": 2147483699,
        "chain_code": "bfad5d31ac996363d635dad2304f9582e81ddd7cc8249c3cd5b327706103cb6e"
      }
    },
  ]
}

public_path_mnemonic = "decrease domain rebel erupt sphere festival medal cargo cross hobby release caught run exhaust area taste island exit decorate quote margin inmate heart frog"
public_path = [
    'xpub661MyMwAqRbcGYp55aa3wf9WqTuPGdFnwyhFBALErewiMiBkeDrXsZ6qDbUbawSiHVgqvqobbNdosLY7aJgsNVv4DtwPAWKEjgCaSEjvdBg',
    'xpub69cS8waATyqVK5tryNLyKKHMHzieRM4AQdG5aR9VSe29cJp4EyTrMDLHUi198chSiY86Dh1V57UPCdwSsNUPDKjhSeXvZ3ejvW76pRGFpQe',
    'xpub6AB84inF91Uf26fue9dETg5rkNhDwEsWN2kpB7vJWHHuakuMeKPL7onruexAnWhLkEMv7Rjq2aA1z8h6iz4XX6tfRaiuZY83TQi4MR29UCN']
