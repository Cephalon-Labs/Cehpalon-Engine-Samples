import os,time,json
from pathlib import Path
root=Path('/mnt/d/Cephalon/.worktrees/ara-consumer/.local')
assert not (root/'pg-wsl-anchor.stop').exists()
(root/'pg-wsl-anchor-owned-process.json').write_text(json.dumps({'pid':os.getpid(),'role':'Owned foreground WSL lifetime anchor only; no network listener or host configuration change'})+'\n')
print('Owned WSL lifetime anchor ready',flush=True)
while not (root/'pg-wsl-anchor.stop').exists():time.sleep(.5)
print('Owned WSL lifetime anchor stopped',flush=True)
