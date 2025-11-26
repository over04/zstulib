use zstulib::self_service::security::RSAKeyPair;

fn main() {
    let password = "Abc1099456453";
    let (public_key_exponent, public_key_modulus) = (
        "10001",
        "94dd2a8675fb779e6b9f7103698634cd400f27a154afa67af6166a43fc26417222a79506d34cacc7641946abda1785b7acf9910ad6a0978c91ec84d40b71d2891379af19ffb333e7517e390bd26ac312fe940c340466b4a5d4af1d65c3b5944078f96a1a51a5a53e4bc302818b7c9f63c4a1b07bd7d874cef1c3d4b2f5eb7871",
    );
    let key_pair = match RSAKeyPair::new(public_key_exponent, "", public_key_modulus) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("failed to build RSA key: {err}");
            return;
        }
    };
    let reversed_password: String = password.chars().rev().collect();
    match key_pair.encrypt(&reversed_password) {
        Ok(cipher) => println!("{cipher}"),
        Err(err) => eprintln!("encryption failed: {err}"),
    }
}
