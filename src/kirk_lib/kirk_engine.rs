// void kirk7(u8* outbuff, const u8* inbuff, size_t size, int keyId)
// {
//   AES_ctx aesKey;
//   u8* key = kirk_4_7_get_key(keyId);
//   AES_set_key(&aesKey, key, 128);
//   AES_cbc_decrypt(&aesKey, inbuff, outbuff, size);
// }

pub fn kirk7(expanded_seed: &mut [u8; 144], key: i32) {
    println!("Helloooo")
}