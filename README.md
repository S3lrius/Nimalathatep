# Nimalathatep
Nimalathatep is a Nim shellcode payload generation project that aims to get a stealthy binary inro your hands quickly. All methods use well-known API-call sequences.

# Evasion
AV/EDR avoidance is performed through AES encryption followed by Base64, with the payload itself only being decrypted at runtime. The IV is currently static, but I aim to change this in the future. Compiling to a control panel item is your stealthiest approach for now. 

# Compilation
Ensure you have NIM downloaded from here: https://nim-lang.org/install.html </br>
</br>

Install the winim, ptr_math, and nim crypto prior to compiling with the following commands:</br>
```nimble install winim```</br>
```nimble install nimcrypto```</br>
```nimble install ptr_math``` </br></br>
To compile: </br>
```nim -d:release c .\nimalathatep.nim``` </br>
</br>
<img alt="alt_text" width="1000" src="compilation.PNG" />
</br>

# Usage
Run the executable and give it the desired API method, shellcode file, and output file type: </br> </br>
```.\nimalathatep.exe <apiMethod> <binFile> <outfiletype>``` </br>
</br>
<img alt="alt_text" width="1000" src="payload_creation.PNG" />
</br>

# Defender Check
<img alt="alt_text" width="1000" src="full-usage.gif" />



# To Do
-Generation option to directly place the file into a PDF as an attachment </br>
-Custom unhook stuff </br>
-Add option to pack payload into iso or 7zip </br>

# Credits
Some code bits from: <br>
https://github.com/byt3bl33d3r/OffensiveNim </br>
https://www.ired.team/ </br>
https://github.com/bigb0sss/Bankai <--Initial inspiration

# Disclaimer
Only use this for purposes involving systems that you have been given permission to access and alter. I am not responsible if you do illegal stuff. 

