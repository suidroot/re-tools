#!/usr/bin/python3

import struct

filename = "hello.exe"
hThepefile = open(filename, 'rb')

def unpackdata(file_handle, format, section, offset, length):

    file_handle.seek(section + offset, 0)  # absolute positioning

    content = file_handle.read(length)

    print("Content " + str(content))

    return_val = struct.unpack(format, content)
    print (return_val)
    return return_val

dos_header = {}
pe_header = {}

dos_header['signature'] = unpackdata(hThepefile, '>H', 0, 0x0, 0x2)[0]
dos_header['p_pe_header'] = unpackdata(hThepefile, '<I', 0, 0x3c, 0x4)[0]

# struct PeHeader {
# 	uint32_t mMagic; // PE\0\0 or 0x00004550
# 	uint16_t mMachine;
# 	uint16_t mNumberOfSections;
# 	uint32_t mTimeDateStamp;
# 	uint32_t mPointerToSymbolTable;
# 	uint32_t mNumberOfSymbols;
# 	uint16_t mSizeOfOptionalHeader;
# 	uint16_t mCharacteristics;
# };

# COFF Header
pe_header['sig'] = unpackdata(hThepefile, '>I', dos_header['p_pe_header'], 0x0, 0x4)[0]
pe_header['machine'] = unpackdata(hThepefile, '<H', dos_header['p_pe_header'], 0x4, 0x2)[0]
pe_header['numofsections'] = unpackdata(hThepefile, '<h', dos_header['p_pe_header'], 0x6, 0x2)[0]
pe_header['timedatestamp'] = unpackdata(hThepefile, '>I', dos_header['p_pe_header'], 0x8, 0x4)[0]
pe_header['pointertosymboltable'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0xc, 0x4)[0]
pe_header['numofsymbols'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x10, 0x4)[0]
pe_header['sizeofoptionalheader'] = unpackdata(hThepefile, '<h', dos_header['p_pe_header'], 0x14, 0x2)[0]
pe_header['characteristiscs'] = unpackdata(hThepefile, '<h', dos_header['p_pe_header'], 0x16, 0x2)[0]
pe_header['imagebase'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x30, 0x4)[0]


# struct Pe32OptionalHeader {
# 	uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
# 	uint8_t  mMajorLinkerVersion;
# 	uint8_t  mMinorLinkerVersion;
# 	uint32_t mSizeOfCode;
# 	uint32_t mSizeOfInitializedData;
# 	uint32_t mSizeOfUninitializedData;
# 	uint32_t mAddressOfEntryPoint;
# 	uint32_t mBaseOfCode;
# 	uint32_t mBaseOfData;
# 	uint32_t mImageBase;
# 	uint32_t mSectionAlignment;
# 	uint32_t mFileAlignment;
# 	uint16_t mMajorOperatingSystemVersion;
# 	uint16_t mMinorOperatingSystemVersion;
# 	uint16_t mMajorImageVersion;
# 	uint16_t mMinorImageVersion;
# 	uint16_t mMajorSubsystemVersion;
# 	uint16_t mMinorSubsystemVersion;
# 	uint32_t mWin32VersionValue;
# 	uint32_t mSizeOfImage;
# 	uint32_t mSizeOfHeaders;
# 	uint32_t mCheckSum;
# 	uint16_t mSubsystem;
# 	uint16_t mDllCharacteristics;
# 	uint32_t mSizeOfStackReserve;
# 	uint32_t mSizeOfStackCommit;
# 	uint32_t mSizeOfHeapReserve;
# 	uint32_t mSizeOfHeapCommit;
# 	uint32_t mLoaderFlags;
# 	uint32_t mNumberOfRvaAndSizes;
# };
# Stndard COFF Fields
pe_header['magic'] = unpackdata(hThepefile, '<H', dos_header['p_pe_header'], 0x18, 0x2)[0]
pe_header['majorlinkerversion'] = unpackdata(hThepefile, '<B', dos_header['p_pe_header'], 0x1a, 0x1)[0]
pe_header['minorlinkerversion'] = unpackdata(hThepefile, '<B', dos_header['p_pe_header'], 0x1b, 0x1)[0]
pe_header['sizeofcode'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x1c, 0x4)[0]
pe_header['sizeofinitizedcode'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x20, 0x4)[0]
pe_header['sizeofuninitizedcode'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x24, 0x4)[0]
pe_header['addressofentrypoint'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x28, 0x4)[0]
pe_header['baseofcode'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x2c, 0x4)[0]
pe_header['baseofdata'] = unpackdata(hThepefile, '<I', dos_header['p_pe_header'], 0x30, 0x4)[0]



print(pe_header)
# print(hex(pe_header['pe_sig']))
for i in pe_header:
    print (i, hex(pe_header[i]))