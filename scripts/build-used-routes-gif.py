from pathlib import Path
from PIL import Image
import json
root=Path(__file__).resolve().parents[1]
folder=root.parent/'.gif_capture_used_routes'
manifest=json.loads((folder/'manifest.json').read_text())
files=sorted(folder.glob('*.png'))
assert len(files)==363
height=max(item['height'] for item in manifest)
frames=[]
for file in files:
    with Image.open(file) as source:
        source=source.convert('RGB')
        canvas=Image.new('RGB',(1760,height),'#0a121a')
        # Center each tightly framed segment on the fixed GIF canvas.
        canvas.paste(source,(0,(height-source.height)//2))
        frames.append(canvas.quantize(colors=128,method=Image.Quantize.FASTOCTREE))
durations=[330]*len(frames)
for index in (120,241,362): durations[index]=2500
output=root/'assets/ARTEX_vs_Pre2023_Three_Infrastructures_Used_Routes.gif'
frames[0].save(output,save_all=True,append_images=frames[1:],duration=durations,loop=0,optimize=False,disposal=2)
with Image.open(output) as gif:
    assert gif.n_frames==363
    total=0
    for index in range(gif.n_frames):
        gif.seek(index)
        total+=gif.info['duration']
    print(f'{output}: {gif.n_frames} frames, {gif.size}, {total/1000}s, {output.stat().st_size/1048576:.1f} MB')
