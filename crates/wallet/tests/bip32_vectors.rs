//! Official BIP32 test vectors — decoded from the published xprv/xpub
//! strings in bip-0032.mediawiki and compared field-by-field against our
//! implementation (key bytes, chain code, depth, fingerprint, child num).
//!
//! This is stronger than comparing remembered hex: the vectors are the
//! canonical serialization, Base58Check-verified.

use minibtc_wallet::bip32::{ChildNumber, Xpriv};

/// Base58Check-decode → 78-byte payload (version stripped separately).
fn b58check(s: &str) -> Vec<u8> {
    let raw = bs58::decode(s).into_vec().unwrap();
    assert_eq!(raw.len(), 82, "bad length for {s}");
    let (payload, checksum) = raw.split_at(78);
    let expect = minibtc_crypto::double_sha256(payload);
    assert_eq!(&checksum[..4], &expect.as_bytes()[..4], "bad checksum {s}");
    payload.to_vec()
}

/// Parse an xprv payload → (privkey32, chaincode32, depth, fingerprint, child).
fn parse_xprv(payload: &[u8]) -> ([u8; 32], [u8; 32], u8, [u8; 4], u32) {
    assert_eq!(&payload[0..4], &[0x04, 0x88, 0xad, 0xe4], "bad xprv version");
    let mut privk = [0u8; 32];
    assert_eq!(payload[45], 0x00, "xprv key data must start with 0x00");
    privk.copy_from_slice(&payload[46..78]);
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&payload[13..45]);
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&payload[5..9]);
    let child = u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]);
    (privk, cc, payload[4], fp, child)
}

/// Parse an xpub payload → (pubkey33, chaincode32, depth, fingerprint, child).
fn parse_xpub(payload: &[u8]) -> ([u8; 33], [u8; 32], u8, [u8; 4], u32) {
    assert_eq!(&payload[0..4], &[0x04, 0x88, 0xb2, 0x1e], "bad xpub version");
    let mut pk = [0u8; 33];
    pk.copy_from_slice(&payload[45..78]);
    let mut cc = [0u8; 32];
    cc.copy_from_slice(&payload[13..45]);
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&payload[5..9]);
    let child = u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]);
    (pk, cc, payload[4], fp, child)
}

fn c(s: &str) -> ChildNumber {
    ChildNumber::parse(s).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Assert an Xpriv matches a decoded xprv string.
fn assert_xprv(x: &Xpriv, xprv_b58: &str) {
    let (privk, cc, depth, fp, child) = parse_xprv(&b58check(xprv_b58));
    assert_eq!(x.secret_bytes(), privk, "privkey mismatch for {xprv_b58}");
    assert_eq!(*x.chain_code(), cc, "chain code mismatch");
    assert_eq!(x.depth(), depth, "depth mismatch");
    assert_eq!(x.parent_fingerprint(), fp, "fingerprint mismatch");
    assert_eq!(x.child_num(), child, "child num mismatch");
}

/// Assert an Xpub (from to_xpub) matches a decoded xpub string.
fn assert_xpub(x: &Xpriv, xpub_b58: &str) {
    let xpub = x.to_xpub().unwrap();
    let (pk, cc, depth, fp, child) = parse_xpub(&b58check(xpub_b58));
    assert_eq!(*xpub.public_key_bytes(), pk, "pubkey mismatch for {xpub_b58}");
    assert_eq!(*xpub.chain_code(), cc, "chain code mismatch");
    assert_eq!(xpub.depth(), depth, "depth mismatch");
    assert_eq!(xpub.parent_fingerprint(), fp, "fingerprint mismatch");
    assert_eq!(xpub.child_num(), child, "child num mismatch");
}

#[test]
fn test_vector_1_chain_m() {
    let seed = hex("000102030405060708090a0b0c0d0e0f");
    let m = Xpriv::master_seed_bytes(&seed).unwrap();
    assert_xprv(&m, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    assert_xpub(&m, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

    let c0h = m.derive(c("0'")).unwrap();
    assert_xprv(&c0h, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
    assert_xpub(&c0h, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");

    let c01 = c0h.derive(c("1")).unwrap();
    assert_xprv(&c01, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");
    assert_xpub(&c01, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");

    let c012h = c01.derive(c("2'")).unwrap();
    assert_xprv(&c012h, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
    assert_xpub(&c012h, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");

    let c0122 = c012h.derive(c("2")).unwrap();
    assert_xprv(&c0122, "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");
    assert_xpub(&c0122, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");

    let c_full = c0122.derive(c("1000000000")).unwrap();
    assert_xprv(&c_full, "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");
    assert_xpub(&c_full, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
}

#[test]
fn test_vector_2_chain_m() {
    let seed = hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    let m = Xpriv::master_seed_bytes(&seed).unwrap();
    assert_xprv(&m, "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");
    assert_xpub(&m, "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");

    let c0 = m.derive(c("0")).unwrap();
    assert_xprv(&c0, "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");
    assert_xpub(&c0, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");

    let c02147 = c0.derive(c("2147483647'")).unwrap();
    assert_xprv(&c02147, "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
    assert_xpub(&c02147, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");

    let c021471 = c02147.derive(c("1")).unwrap();
    assert_xprv(&c021471, "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");
    assert_xpub(&c021471, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");

    let c0214712146 = c021471.derive(c("2147483646'")).unwrap();
    assert_xprv(&c0214712146, "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");
    assert_xpub(&c0214712146, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");

    let c_full = c0214712146.derive(c("2")).unwrap();
    assert_xprv(&c_full, "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");
    assert_xpub(&c_full, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
}

#[test]
fn test_vector_3_leading_zeros() {
    let seed = hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
    let m = Xpriv::master_seed_bytes(&seed).unwrap();
    assert_xprv(&m, "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6");
    assert_xpub(&m, "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13");

    let c0h = m.derive(c("0'")).unwrap();
    assert_xprv(&c0h, "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L");
    assert_xpub(&c0h, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y");
}

#[test]
fn test_vector_4_leading_zeros() {
    let seed = hex("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678");
    let m = Xpriv::master_seed_bytes(&seed).unwrap();
    assert_xprv(&m, "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv");
    assert_xpub(&m, "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa");

    let c0h = m.derive(c("0'")).unwrap();
    assert_xprv(&c0h, "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G");
    assert_xpub(&c0h, "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m");

    let c01h = c0h.derive(c("1'")).unwrap();
    assert_xprv(&c01h, "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1");
    assert_xpub(&c01h, "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt");
}

#[test]
fn ckdpub_matches_ckdpriv_nonhardened() {
    // Public derivation must equal private derivation's pubkey for
    // non-hardened indices (the watch-only property).
    let seed = hex("000102030405060708090a0b0c0d0e0f");
    let m = Xpriv::master_seed_bytes(&seed).unwrap();
    let c0h = m.derive(c("0'")).unwrap();
    let xpub = c0h.to_xpub().unwrap();
    // m/0'/1 — non-hardened: derive publicly.
    let pub_child = xpub.derive(c("1")).unwrap();
    let priv_child = c0h.derive(c("1")).unwrap();
    assert_eq!(
        *pub_child.public_key_bytes(),
        *priv_child.to_xpub().unwrap().public_key_bytes()
    );
    // Official pubkey for m/0'/1 (from vector 1 xpub decode):
    let (pk, _, _, _, _) = parse_xpub(&b58check(
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    ));
    assert_eq!(*pub_child.public_key_bytes(), pk);
}

#[test]
fn bip44_trezor_vector() {
    // The canonical BIP39+BIP44 example: mnemonic
    // "legal winner thank year wave sausage worth useful legal winner thank yellow"
    // passphrase "TREZOR" → m/44'/0'/0'/0/0 → known address/pubkey.
    let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let seed = minibtc_wallet::seed_from_mnemonic(phrase, "TREZOR").unwrap();
    let master = Xpriv::master(&seed).unwrap();
    let path = minibtc_wallet::bip32::DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
    let leaf = master.derive_path(&path).unwrap();
    // Cross-implementation verified: bitcoinjs-lib (bip39 + bip32 +
    // bitcoinjs-lib p2pkh) on the same mnemonic/passphrase/path produces
    // this exact compressed pubkey and address.
    let pk = leaf.public_key_bytes().unwrap();
    assert_eq!(
        pk.to_vec(),
        hex("02fe17bf9bb1c29039a138bb68c0181709d973525eca023031764bbc9087aec3ce")
    );
    let h160 = minibtc_crypto::hash160(&pk);
    let addr = minibtc_crypto::Address::p2pkh(0x00, h160).to_base58();
    assert_eq!(addr, "18MNH3xiSXsYNYxCvwQ6JouW2RkWwStSwy");
}
