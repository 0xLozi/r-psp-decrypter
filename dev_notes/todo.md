
CREATE 2 DECRYPT PRX: ONE FOR IN-PLACE DECRYPTION AND SECOND ONE FOR OUT-PLACE DECRYPTION

I have to do this since sometimes while doing the prx_decryption function, sometimes they use the same pointer as the decryption way and also for storing purposes. Which can lead to race conditions and do werid things. That's why in my custom decrypt_prx I haven't included an outbuf parameter, bcz I thought since it was constantcly doing in-place decryption, it wouldn't change the way of decrypting things and then store the decryption result in another buffer. But inside psar_decrypter.rs. What it does it exactly that: Performing an "out-place" decryption...
So my  architecture desing is to create a second function called decrypt_prx_out_place and then renmame "decrypt_prx" for "decrypt_prx_in_place"

With that thing in mind I can make sure that I don't have to create a third buffer to store the results and try to move bits and that sort of thing too much...

So the in-place decryption might be like this
encrypted data -> Decrypt -> Store -> same buffer

out_place decryption:
input buffer -> encrypted data -> decrypt -> store -> output buffer
