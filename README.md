# Hellsgate
*Undetectable Loader for Cobalt Strike Using Syscalls And A External Shellcode*

# Features: 
* Using `Syscalls` from Hellsgate tech
* loading the shellcode from a `encrypted` bin file
* ability to download the shellcode file from a website 

# ALL YOU NEED:
* python`3` for the encoder
* visual studio 2017 or above 
* cobalt strike; download it from [here](https://github.com/JUICY00000/Cobalt4.4)

# USAGE:
* first generate your payload file, from cobalt strike as `x64` raw 
* then encrypts it with the [binencoder.py](https://github.com/JUICY00000/HellLoader/blob/main/HellsGate/binencoder.py)
`Ex: binencoder.py payload.bin` 
* upload `result.bin` ; which is your encrypted payload file to a website and copy the link of download to your code
   `Ex: the link can be 'raw' / 'download' from 'github' or 'gitlab' or any other website u can download from` 
* after u have ur link copied, paste it in [Download.cpp](https://github.com/JUICY00000/HellLoader/blob/b5eca7068d47af8265c26bdf36a1f65783debc63/HellsGate/HellsGate/HellsGate/Download.cpp#L16)
* then compile it as x64 release in visual studio 2017 (or above)
* its done


# More For You:
* you can execute anti sandbox functions before the download of the payload, and possibly change the link to a good binary instead of the shellcode .
* this way the loader will download a known good binary [make sure its signed by microsoft for extra]
* so when we are in a sandbox we will download a good software, else a our shellcode

# Based on : 
* https://github.com/am0nsec/HellsGate


