### psp_decrypt_psar
This verifies the first "PSAR" magic word, creates a 3MB RAM buffers (data_1, data_2) and starts de init process

### psp_psar_init
It reads the global file headers to figure out what kind of PSAR we are dealing with
Key actions:
- Checks if the file is already decrypted (m33 custom firmware)
- Sets the OVERHEAD measuring tape (Ox150 for official, 0 for customs)
- Sets the initial ctx.i_base in order make the program know exactly where the first file container starts.

### decode_block
Is the secure wrapper for the hardware decryption simulator
- **The Fast path**: If the file is already decrypted, just safely copies the bytes and exits
- **The Bumber**: If encrypted, it copies cb_in + 0x10 into RAM. This creates a 16-byte "garbage" safety bumper so the clumsy KIRK hardware stamping machine doesn't cause a Segmentation Fault when it over-reads.
- Then it calls the actual `decrypt_prx` engine, passing None for the seed so the hardware extracts it automatically.

### demangle_psar_header
For PSAR versions newer than v1, Sony tried to hide the headers by **mangling** them. This function runs an **XOR operation** starting at offset 0x20 (skipping the first 32 bytes) to descramble the data before handing it to the KIRK engine.


### get_version
```c
char version[10];
strncpy(version, GetVersion((char *)data1+0x10), 10);
version[9] = '\0';

printf("Firmware version %s.\n", version);
if (version[1] != '.' || strlen(version) != 4) {
    printf("Invalid version!?\n");
    return 1;
}
int intVersion = (version[0] - '0') * 100 + (version[2] - '0') * 10 + version[3] - '0';
int table_mode;
```
What it does "string copy" is "Take the memory address of data_1, skip forwards by 16 bytes, and start reading from there".
Then... Why not `from_le_bytes()`? Because this isn't a binary integer; **it's human-readable ASCII text**.
`from_le_bytes()` -> for computer numbers, not text strings.

#### Meaning of `version[9] = '\0'`
C-strins are dangerous because they don't know their own length; they just keep reading memory until they reach a null byte (`\0`). `strncpy` copies 10 bytes, but if the source string didn't have a null byte, `printf()` would crash the program by reading forever...

### Explanation about the werid ASCII math (`version[0] - '0'`)
The programmer needs to turn "3.80" into the integer 380 so he can use it in `if/else` statements like below.
In computer memory: '3' has a numeric value of 51. the character '0' has a value of 48
So... If you substract them (51-48) you get "3". They are extracting the first figit, multiplying by 100 (`3*100`) grabbing the third character (skipping the dot), multiplying it by 10 (`8*10`), and adding it all up to get 380.

#### How can we do this in rust?
Rust's standard library is powerful with text. Therefore we don't need pointer math, manual null bytes, or ASCII substraction.

---
### table_modes
Sony released firmware update -> Hackers would eventually figure out how to decrypt it by extracting the secret keys

Sony couldn't change the physical KIRK hardware chip inside the consoles -> They chancged the software locks layered on top of it.

Sony releases a new firmware update -> scrambled the PSAR Headers differently -> new cryptographic keys to distract the hackers

- **Pre-3.80** (`table__mode = 0`): The original classic security
- **Firmware 3.80** (`table__mode = 1`): Sony saw that hackers were reading shipping labels (SIZE_A), so they started mangling (XOR scrambling like we did before yey!!!) the headers.
- **Firmware 4.xx** (`table_mode = 2`): Sony changed the scrambling tables and decryption keys again.
- **Firmware 5.xx and 6.xx** (`table_mdoe = 3, 4, 5`): Sony rotated the keys and added new layers of obfuscation to stop Custom Firmware (5.00 M33 or 6.60 PRO) from being built.

---
### creating folders in psar decryption
Sony PSAR file (EBOOT.PBP) is a giant flat-pack that contains brand-new PSP operating system.

If a normal hacker user runs this update, the PSP decrypts the PSAR in memory and overwrites the physical flash memory chips soldered onto the PSP's motherboard.

**Hacker dilemma:** If the hacker runs the officail update, Sony's new code will overwrite their hacked system, patch all the security vulnerabilities and lock them out of their console forever.
**Hacker solution:** Instead of installing the update into the console, they built this tool to safely "unpack the giant flat-pack" on their computer screen or Memory Stick. So, by creating folders that mimics the original physical chips, they can safely study Sony's new branch code without destroying their own console (well, patch his own console)
that's when pspPSARGetNextFile() comes: checks if the filename is scrambled, and then drops the decrypted file right into those folders that the program just created.

---
### 439 line of code explanation
`0x78` and `0x9C` is the universal signature for zlib compression.
In other words:
- `0x78` Tells the computer that the data is compressed using the Deflate algorithm with a 32KB window
- `0x9C` Tells the computer that this was compressed by using the default compression level
So when Sony packed the EBOOT.PBP update, they didn't just encrypt the files, they zipped them first in order to save space!!!

So, if the cb_expanded number is greater than zero, this means that the file we are looking at is compressed.
- `cb_out = DecodeBlock(...)` what it does is asking KIRK to decrypt that physical chunk of data. And data_out now holds the decrypted payload (but it still zipped!!!)
- `cb_out > 10`: A valid zlib zip file has headers that tak eup a few bytes, so if the decrypted data is less than 10 bytes long, it's definitely garbage!!!
- `data_out[0] == 0x78`: What the hacker does here is verifying if the decryption actually worked
- `gunzip(...)` Takes the zipped data from data_out, unzips it, and dumps it into the second buffer (data_out_2... I think!!!)
- `if (ret == cb_expanded)` Is a final check that tells if the unzipper output the exact number of bytes the Shipping Label promised, so if that's a yes, then Successss!!!

So a remainder for mi future-self: In C++, they had a custom gunzip function. But in rust I don't need to write a decompressor from scratch since I'm gonna use a standard crate called flate2 (or miniz_oxide... I'll figure it out later)




