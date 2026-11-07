#!/usr/bin/env python3
"""PureDarwin's libc++.1.dylib (20.5) has std::uncaught_exceptions() as an abort ("not yet implemented"); iostream sentries
inside the library call it. Replaces its first bytes by `xor eax,eax; ret` (no exception in flight).

  patch_libcxx.py <in> <out>
"""
import subprocess
import sys

src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, 'rb').read())
out = subprocess.run(['nm', '-m', src], capture_output=True, text=True, check=True).stdout
offset = None
for line in out.splitlines():
    if line.endswith('__ZSt19uncaught_exceptionsv') and '(__TEXT,__text)' in line:
        offset = int(line.split()[0], 16)
if offset is None:
    sys.exit('uncaught_exceptions not found')
# __TEXT starts at file offset 0 and vm address 0 in PureDarwin's libc++
assert bytes(data[offset:offset + 1]) != b'\x31', 'already patched'
data[offset:offset + 3] = b'\x31\xc0\xc3'
open(dst, 'wb').write(data)
print('patched uncaught_exceptions at', hex(offset))
