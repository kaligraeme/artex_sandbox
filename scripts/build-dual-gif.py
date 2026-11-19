from pathlib import Path
from PIL import Image
import json
import os
root=Path(__file__).resolve().parents[1]
mode=os.environ.get('DUAL_MODE','baseline')
src=root.parent/('.gif_capture_dual' if mode=='baseline' else f'.gif_capture_dual_{mode}')
manifest=json.loads((src/'manifest.json').read_text())
sheet=Image.new('RGB',(720*4,405*3))
for k,i in enumerate([0,10,20,30,40,50,65,80,95,110,130,145]):
 with Image.open(src/f'{i:03d}.png') as im:
  im.thumbnail((720,405));sheet.paste(im,((k%4)*720,(k//4)*405))
palette=sheet.quantize(colors=256,method=Image.Quantize.MEDIANCUT)
frames=[]
for i in range(manifest['frames']):
 with Image.open(src/f'{i:03d}.png') as im:frames.append(im.convert('RGB').quantize(palette=palette,dither=Image.Dither.NONE))
out=root/'assets'/('ARTEX_vs_PreLLM_dual_30s.gif' if mode=='baseline' else f'ARTEX_vs_PreLLM_dual_{mode}_30s.gif')
frames[0].save(out,save_all=True,append_images=frames[1:],duration=[200]*145+[1000],loop=0,optimize=True,disposal=1)
with Image.open(out) as gif:
 total=0
 for i in range(gif.n_frames):gif.seek(i);total+=gif.info['duration']
 assert total==30000
 assert gif.size==(2880,1620)
 assert gif.info['loop']==0
 gif.seek(gif.n_frames-1);gif.convert('RGB').save(src/'final-check.png')
 print(json.dumps({'file':str(out),'seconds':total/1000,'frames':gif.n_frames,'size':gif.size,'MiB':round(out.stat().st_size/1048576,2)}))
