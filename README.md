# mzip2elf
Cisco MZIP to ELF format converter. This script supports:
- Multiple segments
- Several CPU architectures {PowerPC, MIPS, ARM}
- Several compression algorithms for segments {PKZIP, BZ2, LZMA}

IMPORTANT: DO NOT use this script to run the firmware as ELF. This is just POC code.

## Requirements
- Python 3.8 or later because of simpleelf (I only tested on Python 3.11 and 3.12)
- simpleelf
  - In order to install it, execute the command like below. 
```
pip install simpleelf
```

## Usage
Basically, you can just specify a path to a MZIP formatted firmware like this.
```
.\mzip2elf.py .\manipulated_c3750e.bin
```
Then the script parses the MZIP header and decompresses segments and converts it into the ELF format. The output looks like this.
```
[*] Parsing the MZIP header and segment headers
[Header]
{'magic': b'MZIP', 'version': 1, 'entry_point': 12288, 'nsegments': 2, 'unknown_flags': 4097, 'delimiter': <ctypes._endian.c_ulong_be_Array_8 object at 0x000001A81A826850>, 'segments_crc16': xxxxx, 'header_crc16': yyyyy}

[Segment 0]
{'compressed_offset': 168, 'memory_offset': 12288, 'type': 2, 'compressed_size': 15270341, 'decompressed_size': 47031356, 'memory_size': 47031356, 'delimiter': <ctypes._endian.c_ulong_be_Array_8 object at 0x000001A81A8268D0>}

[Segment 1]
{'compressed_offset': 15270509, 'memory_offset': 50331648, 'type': 2, 'compressed_size': 5170268, 'decompressed_size': 18541008, 'memory_size': 27257512, 'delimiter': <ctypes._endian.c_ulong_be_Array_8 object at 0x000001A81A826950>}

[*] Decompressing compressed segments
Segment 0 was successfully decompressed. Before:15270341, After:47031356
Info: The next segment start address on memory 50331648 is bigger than the current start 12288 + size 47031356
Filled out with null bytes. Before:47031356, After:50319360

Segment 1 was successfully decompressed. Before:5170268, After:18541008
Info: The segment size on memory 18541008 is bigger than the decompressed data size 27257512
Filled out with null bytes. Before:18541008, After:27257512

[*] Calculating CRC16 values
Calculated segments crc16: xxxxx
Calculated header crc16: yyyyy

[*] Creating a dummy ELF
Done. The output file has been created as .\manipulated_c3750e.bin.elf
```
Now, you can use the outputted ELF file.

If you want to change the CPU architecture, use "-a" with the architecture. Currently, it supports Power PC (ppc:default), MIPS (mips) and ARM (arm).
For example, Cisco 2950 uses MIPS. In that case, you can use like the command below.
```
.\mzip2elf.py .\manipulated_c2950.bin -a mips
```

For ARM, you can also use "-e" option to change byte order like below.
```
.\mzip2elf.py .\c2960l.bin -a arm -e le
```

## Background
The binwalk command seems to be commonly used to extract decompress segments when I searched on the Internet. Although it works well if the firmware has only one segment, it will not work if it has multiple ones. For example, I have seen that a 3950's firmware has two segments (See the "Usage" section above). In that case, the decompressed code refers different string and global addresses because the second segment, which is the data segment, should have placed at the different address that is written in the MZIP header. Therefore, parsing MZIP header correctly is necessary. That's why I wrote this script.

## Special thanks to these projects
- https://github.com/doronz88/simpleelf
- https://github.com/bvanheu/linux-cisco
