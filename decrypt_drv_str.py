import idautils

# MD5: b001c32571dd72dc28fd4dba20027a88

DEC_FUNC = ["DecryptAsciiStr", "DecryptUnicodeStr"]
#print hex(sd_udp),idc.GetDisasm(sd_udp)

def main():
    for func in DEC_FUNC:
        funcAddr = idc.LocByName(func)
        for addr in idautils.CodeRefsTo(funcAddr,0):
        #    print hex(addr),":"
        #    print "    ", idc.GetDisasm(idc.PrevHead(idc.PrevHead(addr)))
        #    print "    ", idc.GetDisasm(idc.PrevHead(addr))
        #    print "    ", idc.GetDisasm(addr)
        #    print "\n"

            lenAddrInsStr = None
            dataAddrInsStr = None
            lenAddr = None
            dataAddr = None

            dataAddrInsStr = idc.GetDisasm(idc.PrevHead(addr))
            if dataAddrInsStr.find("offset") > 0:
                lenAddrInsStr = idc.GetDisasm(idc.PrevHead(idc.PrevHead(addr)))
            else:
                dataAddrInsStr = idc.GetDisasm(idc.PrevHead(idc.PrevHead(addr)))
                if dataAddrInsStr.find("offset"):
                    lenAddrInsStr = idc.GetDisasm(idc.PrevHead(idc.PrevHead(idc.PrevHead(addr))))
                else:
                    continue
            
            try:
                dataAddr = long(dataAddrInsStr.split("_")[1], base=16)
                lenAddr = idc.Dword(long(lenAddrInsStr.split("_")[1], base=16))

                if func == "DecryptUnicodeStr":
                    DecryptUnicodeStr(dataAddr, lenAddr)
                else:
                    DecryptAsciiStr(dataAddr, lenAddr)
            except Exception:
                continue

def DecryptAsciiStr(dataAddr, dataLen):
    currByteAdrr = None
    nextByteAddr = None

    for index in range(0, dataLen):
        currByteAdrr = dataAddr + 1*index
        nextByteAddr = dataAddr + 2*index

        decrypt_val = idc.Byte(nextByteAddr) ^ 0xC
        
        PatchByte(currByteAdrr, decrypt_val)
    
    PatchByte(dataAddr+dataLen, 0x0)
    MakeStr(dataAddr, dataAddr+dataLen)


def DecryptUnicodeStr(dataAddr, dataLen):
    currByteAdrr = None
    nextByteAddr = None

    for index in range(0, dataLen):
        currByteAdrr = dataAddr + 2*index
        nextByteAddr = dataAddr + 4*index

        decrypt_val = idc.Byte(nextByteAddr) ^ 0xC
        
        PatchByte(currByteAdrr, decrypt_val)
    
    PatchByte(dataAddr+2*dataLen, 0x0)

    #make unicode str
    old_type = idc.GetLongPrm(INF_STRTYPE)
    idc.SetLongPrm(idc.INF_STRTYPE, idc.ASCSTR_UNICODE)
    MakeStr(dataAddr, dataAddr+2*dataLen)
    idc.SetLongPrm(idc.INF_STRTYPE, old_type)


if __name__ =="__main__":
    main()
