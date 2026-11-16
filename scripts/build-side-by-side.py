from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
src=root.parent/'.gif_capture_side_by_side'
manifest=json.loads((src/'manifest.json').read_text())
font=ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf',22)
bold=ImageFont.truetype('C:/Windows/Fonts/segoeuib.ttf',29)
frames=[]
for i in range(manifest['frames']):
 im=Image.new('RGB',(2880,1140),'#0b1118');d=ImageDraw.Draw(im)
 d.text((25,9),'PRE-LLM  /  LOCKBIT-STYLE',font=bold,fill='#73e4f4')
 d.text((1460,9),'ARTEX  /  AGENTIC',font=bold,fill='#73e4f4')
 for j in range(2):
  with Image.open(src/f'{i:03d}-{j}.png') as p: im.paste(p,(1440*j,50))
 d=ImageDraw.Draw(im);d.line((1440,0,1440,1100),fill='#466276',width=3)
 d.text((25,1108),'Same focused enterprise · Baseline · Shared modeled clock · Illustrative scenario, not measured field performance',font=font,fill='#a8becd')
 frames.append(im)
# Palette sampled from multiple phases to retain UI colors, paths and text.
sheet=Image.new('RGB',(480*6,190*2),'#0b1118')
for k,i in enumerate([0,4,10,20,28,40,55,70,85,100,110,120]):
 sample=frames[i].copy();sample.thumbnail((480,190));sheet.paste(sample,((k%6)*480,(k//6)*190))
palette=sheet.quantize(colors=256,method=Image.Quantize.MEDIANCUT)
encoded=[im.quantize(palette=palette,dither=Image.Dither.NONE) for im in frames]
out=root/'assets'/'ARTEX_vs_PreLLM_side_by_side.gif'
encoded[0].save(out,save_all=True,append_images=encoded[1:],duration=[250]*120+[3000],loop=0,optimize=True,disposal=1)
with Image.open(out) as gif:
 print('GIF',gif.size,gif.n_frames,'loop',gif.info.get('loop'),'bytes',out.stat().st_size)
 gif.seek(30);gif.convert('RGB').save(root.parent/'side-by-side-demo-check.png')
