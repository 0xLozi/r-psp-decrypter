### Why 2 decrypt prx instead of 1 in rust?
I have to do this since sometimes while doing the prx_decryption function, sometimes they use the same pointer as the decryption way and also for storing purposes. Which can lead to race conditions and do werid things. That's why in my custom decrypt_prx I haven't included an outbuf parameter, bcz I thought since it was constantcly doing in-place decryption, it wouldn't change the way of decrypting things and then store the decryption result in another buffer. But inside psar_decrypter.rs. What it does it exactly that: Performing an "out-place" decryption...
So my  architecture desing is to create a second function called decrypt_prx_out_place and then renmame "decrypt_prx" for "decrypt_prx_in_place"

With that thing in mind I can make sure that I don't have to create a third buffer to store the results and try to move bits and that sort of thing too much...

So the in-place decryption might be like this
encrypted data -> Decrypt -> Store -> same buffer

out_place decryption:
input buffer -> encrypted data -> decrypt -> store -> output buffer

Wait I have a question: Why can't i just create a bool that triggers that measures if I wanna use in-place decryption or out-place? Like for example this one:
```rust
pub fn decrypt_prx(inbuf: &mut [u8], outbuf: Option<&mut [u8]> seed: Option<&[u8; 16]>) -> Result<usize, PspError> {}
```
So if outbuf = None then it means in-place decryption, but if eventually outbuf is Some(&mut [u8]), then we use out-place decryption. Then we don't have to change lot's of things through the code


### Note regards of outbuf type
Why outbuf is `&mut Option<&mut [u8]>`
`outbuf` represents an optional destination buffer for PRX decrytpion
`Some(&mut [u8])` -> Performs an out-of-place decryption and then writes the result into the provided buffer.
&mut is used here because the decryption function needs mutable access to the `Option` and also to the mutable slice contained inside it. Which allows the function to inspect wheter an output buffer exists or not, or so it does, write the decrypted bytes inside of it.
By passing `Option<&mut [u8]>` by value, this would transferr ownership of the `Option` itself into the function. Then Passin `&Option<&mut[u8]>` this only provides an immutable borrow of the `Option`, which is good for inspection but not for what we are looking for (edit the contents of the mutable fat slice that is being wrapper inside Option).
So Passing `&mut Option<&mut [u8]>` i have access to the Option itself, and then mutable access to the output bytes.
The important thing is that The decryptor only needs to write into the existing output buffer; it does not need to change what reference point so. Just to clarify...