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






