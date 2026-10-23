"""Verify repository release checksums without installing or changing PHP."""
from pathlib import Path, PurePosixPath
import hashlib

root = Path(__file__).resolve().parents[1]
for line in (root / 'SHA256SUMS').read_text().splitlines():
    digest, name = line.split('  ', 1)
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise SystemExit('Unsafe manifest path')
    path = root / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit('Checksum mismatch: ' + name)
print('All release checksums match.')
