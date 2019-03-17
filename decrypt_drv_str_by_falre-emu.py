import idc
import flare_emu
import unicorn as UC

# MD5: b001c32571dd72dc28fd4dba20027a88

def decrypt(argv, funcName):
    myEH = flare_emu.EmuHelper()
    print("decrypting...")
    mu = myEH.emulateRange(idc.get_name_ea_simple(funcName), stack = [0, argv[0], argv[1]], memAccessHook=mem_hook)
    decrypted_data =  myEH.getEmuBytes(argv[0], argv[1])
    print('decrypted: {}'.format(decrypted_data))
    # make string in idb file
    if funcName == "DecryptAsciiStr":
        # make ascii str
        idc.MakeStr(argv[0], argv[0]+argv[1])
    if funcName == "DecryptUnicodeStr":
        # make unicode str
        old_type = idc.GetLongPrm(INF_STRTYPE)
        idc.SetLongPrm(idc.INF_STRTYPE, idc.ASCSTR_UNICODE)
        idc.MakeStr(argv[0], argv[0]+(argv[1]*2))
        idc.SetLongPrm(idc.INF_STRTYPE, old_type)
    return decrypted_data


def call_hook(address, argv, funcName, userData):
    print('{}:call fun:{}'.format(hex(address),funcName))
    print("argv:", hex(argv[0]), argv[1:])
    eh = userData["EmuHelper"]
    dec = decrypt(argv, funcName)
    

def mem_hook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):
    #if accessType == UC.UC_MEM_READ:
    #    print("Read: ", hex(memAccessAddress), memAccessSize, hex(memValue))
    if accessType == UC.UC_MEM_WRITE:
        #print("Write: ", hex(memAccessAddress), memAccessSize, hex(memValue))
        if memAccessSize == 1:
            idc.PatchByte(memAccessAddress, memValue)
        elif memAccessSize == 2:
            idc.PatchWord(memAccessAddress, memValue)
        elif memAccessSize == 4:
            idc.PatchDword(memAccessAddress, memValue)


print("Start decrypting >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
eh = flare_emu.EmuHelper()    
eh.emulateRange(0x100038C4, endAddr=0x10004445, callHook=call_hook, count=10000)
print('>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Done.')