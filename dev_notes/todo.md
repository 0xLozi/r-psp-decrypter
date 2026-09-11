
# Next to-do
**Confirmed**
iv is not actually used by the AES decryption routine.
Therefore, in order to mimic the original behavior, iv can be initialized whit all zeroes.
This is valid since X ^ 0 = X.

**AES key / set_keys**
In the original implementation, set_keys receives a reference to a global variable, something like aes_key_cmd1 I don't remember right now.
That global variable is initialized by a random routine (I think kirk_cm2, which it doesn't make any sense at all...).
In Rust, making this global state work it would introduce unnecessary complexity.

**Design decision**
Instead of reproducing the global variable exactly, we create a temporary AES key inside kirk_cmd1.
This should be cheap enough since it's not that big lmao, and avoids unnecessary global mutable issues in Rust.

The goal is to reproduce the behavior that I'm currently seeing of the original implementation rather than its exact global-state architecture just for safetyness


**Next**
let decryptor_keys = Aes128CbcDec::from_cipher(self.aes_kirk1.clone(), &iv.into());
Understand again what the hell cipher means...
