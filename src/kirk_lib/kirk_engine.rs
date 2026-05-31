use aes::Aes128Dec;
// void kirk7(u8* outbuff, const u8* inbuff, size_t size, int keyId)
// {
//   AES_ctx aesKey;
//   u8* key = kirk_4_7_get_key(keyId);
//   AES_set_key(&aesKey, key, 128);
//   AES_cbc_decrypt(&aesKey, inbuff, outbuff, size);
// }

// interesting, this means the key has 128 bits of size
//   AES_set_key(&aesKey, key, 128);
// This means that they use CBC method, which is Cipher Block Chaining
//   AES_cbc_decrypt(&aesKey, inbuff, outbuff, size);
// So the method of decryption is AES-128-CBC, and I don't see any weird padding. Therefore I might use that
pub fn kirk7(expanded_seed: &mut [u8; 144], key: i32) {
    println!("Helloooo")
}