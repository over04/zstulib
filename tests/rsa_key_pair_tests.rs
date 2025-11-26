use zstulib::self_service::security::RSAKeyPair;

#[test]
fn rsa_encrypt_decrypt_round_trip() {
    let key = RSAKeyPair::new("11", "115f1", "12977").unwrap();
    let plaintext = "RustRSA";
    let cipher = key.encrypt(plaintext).unwrap();
    assert!(!cipher.is_empty());
    let recovered = key.decrypt(&cipher).unwrap();
    assert_eq!(recovered, plaintext);
}
