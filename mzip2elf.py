import sys
import os
import io
import bz2
import zipfile
import lzma
import tempfile
import argparse
from ctypes import *

# pip install simpleelf
from simpleelf.elf_builder import ElfBuilder
from simpleelf import elf_consts

"""
https://github.com/bvanheu/linux-cisco/blob/master/mziptools/mzip.h
struct mzip_header {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_point;
    uint32_t unknown1; // should be something like number of segments
    uint32_t unknown2; // ...
    uint32_t delimiter[8];
    uint16_t segment_crc16;
    uint16_t header_crc16;
    uint32_t header_size;
    uint32_t load_address;
    uint32_t segment_type;
    uint32_t segment_compressed_size;
    uint32_t segment_size;
    uint32_t memory_image_size;
    uint32_t delimiter2[8];
};
"""
class mzip_header_t(BigEndianStructure):
    _fields_ = (
        ('magic', c_char * 4),
        ('version', c_uint32),
        ('entry_point', c_uint32),
        ('nsegments', c_uint32),      # for example, 3750's firmware has two segments and set two here.
        ('unknown_flags', c_uint32), # unknown flags like 0x1001
        ('delimiter', c_uint32*8),
        ('segments_crc16', c_uint16),
        ('header_crc16', c_uint16),
    )

class mzip_segment_header_t(BigEndianStructure):
    _fields_ = (
        ('compressed_offset', c_uint32),
        ('memory_offset', c_uint32),
        ('type', c_uint32),
        ('compressed_size', c_uint32),
        ('decompressed_size', c_uint32),
        ('memory_size', c_uint32),
        ('delimiter', c_uint32*8),
    )

MZIP_HEADER_MAGIC     = b"MZIP"
MZIP_HEADER_VERSION_1 = 0x1

MZIP_SEGMENT_TYPE_UNKNOWN = 0x0
MZIP_SEGMENT_TYPE_PKZIP   = 0x1 # This is common for the segment type.
MZIP_SEGMENT_TYPE_BZ2     = 0x2 # I have seen 3750's firmware has this type.
MZIP_SEGMENT_TYPE_LZMA    = 0x3

def modified_crc16_ccitt(data: bytes, crc=0):
    table = [ 
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
        0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
        0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
        0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
        0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
        0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
        0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
        0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
        0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
    ]
    
    crc = ~crc & 0xffff
    for byte in data:
        crc = ((crc << 8) & 0xffff) ^ table[((crc >> 8) & 0xffff) ^ byte & 0xff] & 0xffff
    return ~crc & 0xffff # tilde is important !!

def getdict(strct):
    return dict((field, getattr(strct, field)) for field, _ in strct._fields_)

def get_mzip_header(header_data):
    buffer = io.BytesIO(header_data)
    mz_header = mzip_header_t()
    buffer.readinto(mz_header)
    return mz_header

def get_mzip_segment_header(segment_header_data):
    buffer = io.BytesIO(segment_header_data)
    mz_segment_header = mzip_segment_header_t()
    buffer.readinto(mz_segment_header)
    return mz_segment_header

def get_mzip_segment_headers(fd, header, read_bytes):
    for i in range(header.nsegments):
        seg_header_data = fd.read(sizeof(mzip_segment_header_t))
        read_bytes += sizeof(mzip_segment_header_t)
        if sizeof(mzip_segment_header_t) != len(seg_header_data):
            print("Error! Acuqired data size {} is not enough size of the segment structure {}".format(len(seg_header_data), sizeof(mzip_segment_header_t)))
            return
        seg_header = get_mzip_segment_header(seg_header_data)
        yield seg_header_data, seg_header, read_bytes

def get_mzip_segment_data(fd, s):
    fd.seek(s.compressed_offset)
    seg_comp_data = fd.read(s.compressed_size)
    seg_data = None
    if s.type == MZIP_SEGMENT_TYPE_BZ2:
        seg_data = bz2.decompress(seg_comp_data)
    elif s.type == MZIP_SEGMENT_TYPE_PKZIP:
        with zipfile.ZipFile(io.BytesIO(seg_comp_data), 'r') as f:
            #print(f.namelist())
            seg_data = f.read('-')
    elif s.type == MZIP_SEGMENT_TYPE_LZMA:
        seg_data = lzma.decompress(seg_comp_data)
    else:
        print("Error! The segment type {} is not supported".format(s.type))
    if seg_data and s.decompressed_size != len(seg_data):
        print("Error! Decompressed data size {} does not match with the header size {}.".format(len(seg_data), s.decompressed_size))
        return None, None
    return seg_data, seg_comp_data

def create_dummy_elf(fd, header, seg_headers, segs_data, arch="ppc", endian="be", bitness=32):
    arch_const = elf_consts.EM_PPC
    if arch == "ppc": # for 3750
        pass
    elif arch == "mips": # for 2950
        arch_const = elf_consts.EM_MIPS
    elif arch == "arm": # for 1000 and 2960l
        arch_const = elf_consts.EM_ARM
    else:
        print("Error! Unknown CPU architecture.")
        return None

    endian_str = ">"
    if endian == "be":
        pass
    elif endian == "le":
        endian_str = "<"
    else:
        print("Error! Unknown endian.")
        return None
    
    bitness_const = elf_consts.ELFCLASS32
    if bitness == 32:
        pass
    elif bitness == 64:
        bitness_const = elf_consts.ELFCLASS64
    else:
        print("Error! Unknown bitness.")
        return None
    
    e = ElfBuilder(bitness_const) # Bitness (32-bit / 64-bit)
    e.set_endianity(endian_str) # Endian (Big endian is for ppc and mips)
    e.set_machine(arch_const) # Power PC, MIPS or ARM
    e.set_entry(header.entry_point)

    # add code segment
    text_address = seg_headers[0][1].memory_offset
    text_buffer = segs_data[0]
    e.add_segment(text_address, text_buffer, 
        elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X)

    # add a code section inside the first segment
    code_address = text_address
    code_size = len(text_buffer)
    e.add_code_section(code_address, code_size, name='.text')
    
    # add other segments
    for i, (sh, sd) in enumerate(zip(seg_headers[1:], segs_data[1:])):
        e.add_segment(sh[1].memory_offset, sd, 
            elf_consts.PF_R | elf_consts.PF_W)
        #data_address = sh.memory_offset
        #data_size = sh.memory_size
        #e.add_empty_data_section(data_address, data_size, name='.data{}'.format(i))

    # get raw elf
    return e.build()

def __main__():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Cisco MZIP to ELF format converter.{}Note that this tool relies on simpleelf. Install it first like with the following command.{}pip install simpleelf'.format(os.linesep, os.linesep))
    parser.add_argument("filename", type=str,
                        help="Input file name (MZIP formatted firmware)")
    parser.add_argument("-a", "--architecture", type=str, choices=["ppc", "mips", "arm"],
                    help="CPU Architecture (default:%(default)s)", default="ppc")
    parser.add_argument("-e", "--endian", type=str, choices=["le", "be"],
                    help="Little/Big endian (default:%(default)s)", default="be")
    parser.add_argument("-b", "--bitness", type=int, choices=[32, 64],
                    help="32/64 Bitness (default:%(default)s)", default=32)
    args = parser.parse_args()

    file_name = args.filename
    file_size = os.stat(file_name)
    arch = args.architecture
    endian = args.endian
    bitness = args.bitness
    
    read_bytes = 0
    f = open(file_name, "rb")
    
    print("[*] Parsing the MZIP header and segment headers")
    header_data = f.read(sizeof(mzip_header_t))
    if sizeof(mzip_header_t) != len(header_data):
        print("Error! Acuqired data size {} is not enough size of the header base structure {}".format(len(header_data), sizeof(mzip_header_t)))
        return
    read_bytes += sizeof(mzip_header_t)
    header = get_mzip_header(header_data)

    print("[Header]")
    print(getdict(header))
    #print(sizeof(mzip_header_t))
    print()
    if header.magic != MZIP_HEADER_MAGIC:
        print("Error! Magic value does not match with \"{}\". {}".format(MZIP_HEADER_MAGIC, header.magic))
        return
    if header.version != MZIP_HEADER_VERSION_1:
        print("Error! Version number does not match with \"{}\". {}".format(MZIP_HEADER_VERSION_1, header.version))
        return

    seg_headers = []
    #seg_headers_data = []
    for i, (seg_header_data, seg_header, read_bytes) in enumerate(get_mzip_segment_headers(f, header, read_bytes)):
        seg_headers.append((i, seg_header, seg_header_data))
        #seg_headers_data.append((i,seg_header_data))
        print("[Segment {}]".format(i))
        print(getdict(seg_header))
        print()

    print("[*] Decompressing compressed segments")
    segs_data = []
    segs_comp_data = []
    prev_seg = None
    
    # Sometimes, segments are not sorted. So we need to sort by the offsets on memory here.
    seg_headers.sort(key=lambda x: x[1].memory_offset)
    for i, (seg_idx, s, sd) in enumerate(seg_headers):
        seg_data, seg_comp_data = get_mzip_segment_data(f, s)
        if not seg_data:
            print("Error! Failed to get the decompressed data.")
            return
        if len(seg_data) != s.decompressed_size:
            print("Error! The decompressed data {} does not match the header size {}".format(len(seg_data), s.decompressed_size))
            return

        print("Segment {} was successfully decompressed. Before:{}, After:{}".format(seg_idx, len(seg_comp_data), len(seg_data)))
        print("Data (20 bytes):", seg_data[:20])
        if s.decompressed_size != s.memory_size:
            if s.decompressed_size < s.memory_size:
                # padding with null bytes for the difference between the decompressed size and the segment size on memory
                print("Info: The segment size on memory {} is bigger than the decompressed data size {}".format(s.decompressed_size, s.memory_size))
                print("Filled out with null bytes. Before:{}, After:{}".format(len(seg_data), len(seg_data) + s.memory_size - s.decompressed_size))
                seg_data += b"\0" * (s.memory_size - s.decompressed_size)
            else:
                print("Error! The segment size on memory {} is smaller than the decompressed data size {}.".format(s.decompressed_size, s.memory_size))
                return

        if len(seg_headers)-1 > i and s.memory_offset + s.memory_size != seg_headers[i+1][1].memory_offset:
            if seg_headers[i+1][1].memory_offset > s.memory_offset + s.memory_size:
                # padding with null bytes in the border between two segments
                filled_bytes = seg_headers[i+1][1].memory_offset - (s.memory_offset + s.memory_size)
                print("Info: The start address on memory of the next segment {} is bigger than the current start {} + size {}".format(seg_headers[i+1][1].memory_offset, s.memory_offset, s.memory_size))
                print("Filled out with null bytes. Before:{}, After:{}".format(len(seg_data), len(seg_data) + filled_bytes))
                seg_data += b"\0" * filled_bytes
            else:
                print("Warning! The start address on memory of the next segment {} is smaller than the current start {} + size {}. The data in the current segment will be overwritten by the range of the next segment.".format(seg_headers[i+1][1].memory_offset, s.memory_offset, s.memory_size))
        print()
        
        segs_data.append(seg_data)
        segs_comp_data.append((seg_idx, seg_comp_data))
    
    f.close()

    print("[*] Calculating CRC16 values")
    sh_crc = modified_crc16_ccitt(b"".join([shd for idx, sh, shd in sorted(seg_headers, key=lambda x: x[0])]), 0)
    seg_crc = modified_crc16_ccitt(b"".join([x[1] for x in sorted(segs_comp_data, key=lambda x: x[0])]), sh_crc)
    print("Calculated segments crc16:", seg_crc)
    if seg_crc != header.segments_crc16:
        print("Warning! The calculated segments crc16 {} does not match with the segment crc on the header {}".format(seg_crc, header.segments_crc16))

    h_crc = modified_crc16_ccitt(header_data[:-2], 0)
    print("Calculated header crc16:", h_crc)
    if h_crc != header.header_crc16:
        print("Warning! The calculated header crc16 {} does not match with the header crc on the header {}".format(h_crc, header.header_crc16))
    print()

    print("[*] Creating a dummy ELF")
    elf = create_dummy_elf(f, header, seg_headers, segs_data, arch, endian, bitness)
    if elf is None:
        return
    of = file_name + '.elf'
    f = open(of, 'wb')
    f.write(elf)
    f.close()
    print("Done. The output file has been created as {}".format(of))

if __name__ == "__main__":
    __main__()
