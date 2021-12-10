# tdxmeasure

This Tool can dump entire TDX event log in TDX guest. Actually it's a rusty program of Intel TDX pytdxmeasure tool.

**Note**: It needs to be executed inside TDX guest to dump event log.

It's partial dump message:
```
=> Read TDEL ACPI Table
00000000  54 44 45 4C 38 00 00 00 01 0A 49 4E 54 45 4C 20  TDEL8.....INTEL 
00000010  45 44 4B 32 20 20 20 20 02 00 00 00 20 20 20 20  EDK2    ....    
00000020  13 00 00 01 00 00 00 00 00 00 01 00 00 00 00 00  ................
00000030  00 B0 10 1B 00 00 00 00                          ........
Revision:     1
Length:       56
Checksum:     0A
OEM ID:       b'INTEL '
Log Lenght:   0x00010000
Log Address:  0x1B10B000

=> Read Event Log Data - Address: 0x1B10B000(0x10000)
==== TDX Event Log Entry - 0 [0x1B10B000] ====
RTMR              : 0
Type              : 3 (EV_NO_ACTION)
Length            : 65
Algorithms Number : 1
  Algorithms[0xC] Size: 384
RAW DATA: ----------------------------------------------
1B10B000  01 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00  ................
1B10B010  00 00 00 00 00 00 00 00 00 00 00 00 21 00 00 00  ............!...
1B10B020  53 70 65 63 20 49 44 20 45 76 65 6E 74 30 33 00  Spec ID Event03.
1B10B030  00 00 00 00 00 02 00 02 01 00 00 00 0C 00 30 00  ..............0.
1B10B040  00                                               .
RAW DATA: ----------------------------------------------
==== TDX Event Log Entry - 1 [0x1B10B041] ====
RTMR              : 0
Type              : 0x8000000B (UNKNOWN)
Length            : 108
event             : b'\tTdxTable\x00\x01\x00\x00\x00\x00\x00\x00\x00\xaf\x96\xbb\x93\xf2\xb9\xb8N\x94b\xe0\xbatVB6\x00\x90\x80\x00\x00\x00\x00\x00'
Algorithms ID     : 12 (TPM_ALG_SHA384)
Digest[0] :
00000000  4C 9D 1D 08 F1 4E 8B D6 80 92 32 CE 54 35 9E 25  L....N....2.T5.%
00000010  B2 0B 24 0D A6 D0 EF AD B8 F2 4E EE 6D 9B 8F 04  ..$.......N.m...
00000020  F1 CD 99 2F 41 5E 74 DF C8 87 95 BE 36 21 96 FC  .../A^t.....6!..
RAW DATA: ----------------------------------------------
1B10B041  01 00 00 00 0B 00 00 80 01 00 00 00 0C 00 4C 9D  ..............L.
1B10B051  1D 08 F1 4E 8B D6 80 92 32 CE 54 35 9E 25 B2 0B  ...N....2.T5.%..
1B10B061  24 0D A6 D0 EF AD B8 F2 4E EE 6D 9B 8F 04 F1 CD  $.......N.m.....
1B10B071  99 2F 41 5E 74 DF C8 87 95 BE 36 21 96 FC 2A 00  ./A^t.....6!..*.
1B10B081  00 00 09 54 64 78 54 61 62 6C 65 00 01 00 00 00  ...TdxTable.....
1B10B091  00 00 00 00 AF 96 BB 93 F2 B9 B8 4E 94 62 E0 BA  ...........N.b..
1B10B0A1  74 56 42 36 00 90 80 00 00 00 00 00              tVB6........
RAW DATA: ----------------------------------------------
```
