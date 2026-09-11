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

## Note regards of Memory Reinterpretation inside descramble function
Since I know that memory reinterpretation can cause undefined behavior, I should focus more about how can I make this safe rather than using the old way that old C++ developers made back then. And this is my choice:
Changing the function signature in order to use `&mut[u8]` So then we can do the math safely and let the Rust Compiler to optimize it!!!

### Another thing which is important for descramble function
The original C++ PSP decryption algorithm (Specially this one: `x1 = (x1 >> rot) | (x1 << (0x20-rot))`) rotates 32-bit integeres circularly in order to ensuere no cryptographic data is lost. So because C/C++ lacks of a native approach (rotation operator), devs had to simulate it by using this: (x >> rot) | (x << (0x20 - rot)) -> Which performs a right shift operation and in order to not lost those bits that were fall of the right edge they perform a shift operation in order to recover those bits and do an OR operation to rotate them "circularly".
#### A better explanation here:
- The right shift (>> rot): Pushes the bits to the right. And normally, bits falling of the edge (which in this case, is the right one) are permanently destroyed.
- The left shift (<< 0x20 - rot): It "rescues" those bits by taking an un-edited data and moves it left by the exact offset needed in order to plase those falling bits into the Most Significant Bit (The far one left) positions.
- Bitwise OR (|), unifies those 2 chain bits together in order to complete the 32-bit circle!!!

#### Rust Refactor
I replaces this bitwise formula by only using the Rust's native .rotate_right(rot) method.

#### Justification
- The rust method explains better the goal (circular rotation) rather than forcing future maintainers of this project to mentally decode wtf I'm doing and do algebra.
- By eliminating the hardcoded 0x20 and math operators y remove the risk of typos, or alignment bugs!!!


#### Why use ctx rather than global variables inside cmd1
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


### Decision regards KIRK_CMD1_ECDSDA_HEADER
```
KIRK_CMD1_ECDSA_HEADER* eheader = (KIRK_CMD1_ECDSA_HEADER*) inbuff;
```
Inside kirk_engine.h we can find the desired struct:
```cpp
typedef struct
{
	u8  AES_key[16];            //0
	u8  header_sig_r[20];           //10
	u8  header_sig_s[20];   //24
	u8  data_sig_r[20];     //38
	u8  data_sig_s[20];     //4C
	u32 mode;                   //60
	u8  ecdsa_hash;             //64
	u8  unk3[11];               //65
	u32 data_size;              //70
	u32 data_offset;            //74  
	u8  unk4[8];                //78
	u8  unk5[16];               //80
} KIRK_CMD1_ECDSA_HEADER; //0x90
```

I can replicate this though, But is not that simple. I can get inspiration by the other struct that I've made which is some-what related to this struct though:
```rust
pub struct PrxType1 {
    pub data: [u8; 0x150],
}

impl PrxType1 {
    /// Construye un nuevo PrxType1 a partir de los datos crudos del archivo.
    pub fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        
        // utilizamos los offsets del C++ original:
        data[0..4].copy_from_slice(&prx[0xD0..0xD4]);       // tag
        data[4..0x18].copy_from_slice(&prx[0xD4..0xE8]);    // sha1 (20 bytes / 0x14)
        data[0x18..0x40].copy_from_slice(&prx[0xE8..0x110]); // unused (40 bytes / 0x28)
        data[0x40..0x80].copy_from_slice(&prx[0x110..0x150]);// kirkBlock parte 1 (64 bytes / 0x40)
        data[0x80..0xD0].copy_from_slice(&prx[0x80..0xD0]);  // kirkBlock parte 2
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);    // prxHeader (128 bytes / 0x80)

        Self { data }
    }

    pub fn decrypt(&mut self, key_id: i32) -> Result<(), KirkError> {
        // En C++ la firma era: kirk7(sha1+0xC, sha1+0xC, 0xA0, key);
        // Nuestro 'sha1' empieza en el offset 4.
        // 4 + 12 (0xC) = 16 (0x10).
        // Si queremos desencriptar 160 bytes (0xA0): 16 + 160 = 176 (0xB0).
        
        // Rust nos obliga a ser explicito y seguros...
        kirk7(&mut self.data[0x10..0xB0], key_id)?;
        
        Ok(())
    }

    pub fn tag(&self) -> &[u8] {
        &self.data[0..4]
    }

    pub fn sha1(&self) -> &[u8] {
        &self.data[4..0x18]
    }

    /// Returns 40 unused bytes
    pub fn unused(&self) -> &[u8] {
        &self.data[0x18..0x40]
    }

    /// Returns KIRK block (144 bytes united)
    pub fn kirk_block(&self) -> &[u8] {
        &self.data[0x40..0xD0]
    }

    // prxHeader (128 bytes / 0x80)
    // Remember, we use this position of the array because here we put everythign into a giant array. Thus we have to copy there instead of 0x00 to 0x80
    /// Devuelve la cabecera final del PRX
    pub fn prx_header(&self) -> &[u8] {
        &self.data[0xD0..0x150]
    }    
```

Like this one, i'ts really good though but I have to make something to that struct (the cpp one) in order to fit it well.






