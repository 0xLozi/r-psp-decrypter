Tomorrow -> Keep Reverse engineering pspDecryptPSAR (Stuck at lines 470...479). Trying to understand why the operation of intVersion is like that.
I already know what they are doing: They are simply taking the version that is being stored at data_1 but moving past 16 bytes (0x10), then they take 10 bytes of that since the char version array is 10 size.
But where I'm struggling is when it doest the intVersion parsing (I think that's what they're doing)
