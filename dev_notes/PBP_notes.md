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






