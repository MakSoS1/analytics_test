"""Render relocation templates for this standalone Arkime directory; no service starts."""
from pathlib import Path
import getpass,grp,os
root=Path(__file__).resolve().parent
for template in (root/'config').glob('*.ini.template'):
    target=template.with_suffix('')
    if target.exists():raise FileExistsError('retain existing config: '+str(target))
    text=template.read_text().replace('@ARKIME_ROOT@',str(root))
    text=text.replace('dropUser=labuser','dropUser='+getpass.getuser()).replace('dropGroup=labuser','dropGroup='+grp.getgrgid(os.getgid()).gr_name)
    target.write_text(text);print(target)
