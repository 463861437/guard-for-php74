"""Create versioned source ZIP and standalone release assets from tracked files."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import zipfile

root = Path(__file__).resolve().parents[1]
version = subprocess.check_output(['bash', str(root / 'php74-patch.sh'), '--version'], text=True).strip()
# The bootstrap is outside the payload, so pinning its payload hash has no
# circular dependency. Never publish a launcher that points to different bytes.
launcher = root / 'install.sh'
text = launcher.read_text()
import re
text, replaced = re.subn(r"(?m)^PG_SHA256='[^']*'$", "PG_SHA256='" + hashlib.sha256((root / 'php74-patch.sh').read_bytes()).hexdigest() + "'", text)
if replaced != 1 or ("PG_VERSION='" + version + "'") not in text:
    raise SystemExit('Bootstrap release version/hash field does not match payload')
launcher.write_text(text)
tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
tracked = sorted(name for name in tracked if name and name != 'SHA256SUMS')
manifest = ''.join(hashlib.sha256((root / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in tracked)
(root / 'SHA256SUMS').write_text(manifest)
out = root / 'dist'; out.mkdir(exist_ok=True)
archive = out / ('guard-for-php74-' + version + '.zip')
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for name in tracked + ['SHA256SUMS']:
        bundle.write(root / name, 'guard-for-php74/' + name)
standalone = out / ('php74-patch-' + version + '.sh')
shutil.copy2(root / 'php74-patch.sh', standalone)
bootstrap = out / 'install.sh'
shutil.copy2(launcher, bootstrap)
for path in (archive, standalone, bootstrap):
    path.with_name(path.name + '.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n')
print('Release assets:', out)
