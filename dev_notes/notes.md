## Dev Notes: Why we add + 0x10 padding to KIRK decryption buffers
**The Code in Question:**
```Rust
// memcpy(pOut, pIn, cbIn + 0x10); // copy a little more for $10 page alignment
// The same would be
// Creating a safety bumper for the hardware decryption engine
p_out[..cb_in + 0x10].copy_from_slice(&p_in[..cb_in + 0x10]);
```
The + 0x10 (16 bytes) is a **sacrificial safety bumper in RAM**. It prevents the hardware decryption simulator from causing a **Segmentation Fault** when processing file sizes that aren't perfectly divisible by 16.

**The Problem:** Clumsy Hardware Block Sizes
The PSP's cryptographic hardware (the KIRK engine) **does not process data byte-by-byte**. It processes data strictly in 16-byte (0x10) blocks.

If we tell the engine to decrypt a file that is exactly 275 bytes long (cb_in = 275), the engine will run **17 times** (covering 272 bytes). To get the remaining 3 bytes, **it drops the 16-byte stamp one final time.**

Because the "stamp" is 16 bytes wide, it grabs the 3 bytes we want, plus 13 bytes of whatever happens to be sitting next to it in memory.

**Possible Danger: Segmentation Faults**
If we only allocated exactly 275 bytes in RAM, those extra 13 bytes the engine tries to read will be out-of-bounds. The operating system will flag this illegal memory access and instantly kill the program with a Segmentation Fault.

### Solution: Safety Bumper
In order to protect the program, we over-allocate the buffer in RAM by copying cb_in + 0x10, so we take our exact target payload, plus the next 16 bytes of literal garbage data form the file, and place it all on the workbench
So when the KIRK engine does its final, clumsy over-read, it hits the **garbage data** we intentionally provided.
Result: The engine doesn't crash and the OS doesn't panic, so we simply ignore the garbage bytes afterwads, 

**IMPORTANT**
This padding is not a structural requirement of Sony's PSAR file format on disk. Sony doesn't care if a file size is divisible by 16. This is strictly a memory management trick used by hackers to keep PC tools from crashing when simulating clumsy hardware.


### PSAR Extraction loop: own notes....
`char name[128]`
what it holds? -> Name of the current file being extraced, pulled from a 272 bytes Shipping Lable (THE SIZE_A). The while loop needs to know what to name the file inside my hard-drive
Problem: Starting in Firmware 5.00, Sony hid filenames... (for example: kd/reboot.bin) doing a hashing algorithm, and as result of that, we have meaningless strings like `is5Dnum`

`cb_expanded`
It holds the target size of the file after it has been decompressed
Many files inside PSAR are zipped to save space. So if the file is compressed, then the decryption engine needs to know exactly how many bytes the file will expand into so it knows when to stop unzipping and avoid something called `Buffer Overflow...`

`pos` (This is the physical coordinate)
It holds the exact byte offset where the current file is locate inside the `.PBP` file
It act as a physical cursor, because there are LOTS OF PRX's modules inside the giant flat-pack, so `pos` updates dynamically every time `pspPSARGetNextFile` is called.

`signcheck`
It holds a flag indicating th ecurrent executable (`prx`) is cryptographically signed by Sony.
So when the PSP tries to run a file, the KIRK chip inspects this seal. And if the file is official, then KIRK executes it!!!



