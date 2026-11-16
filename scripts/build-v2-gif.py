"""Assemble the capture manifest with a shared palette and verify the exported GIF."""
import argparse
import json
from pathlib import Path
from PIL import Image

parser = argparse.ArgumentParser()
parser.add_argument('--frames', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
manifest = json.loads((args.frames / 'manifest.json').read_text(encoding='utf-8'))
assert len(manifest['runs']) == 8
assert {(r['actor'], r['mode']) for r in manifest['runs']} == {(a, m) for a in ['artex', 'pre2023'] for m in ['baseline', 'patch', 'soc', 'combined']}
samples = manifest['frames'][::max(1, len(manifest['frames']) // 30)]
sheet = Image.new('RGB', (240 * 6, 177 * ((len(samples) + 5) // 6)))
for i, item in enumerate(samples):
    with Image.open(args.frames / item['file']) as im:
        im.thumbnail((240, 177))
        sheet.paste(im, ((i % 6) * 240, (i // 6) * 177))
sample_palette = sheet.quantize(colors=192, method=Image.Quantize.MEDIANCUT).getpalette()[:192 * 3]
# Thumbnail sampling loses thin white text and bright semantic strokes. Reserve those colors explicitly.
semantic = ['dce6ee','73e4f4','a8becd','d85b7b','ff7b96','e7afbf','e1bc76','83ecfa','e9bc7c','c0a8f1',
            'f0f3f6','aabccc','101d29','0b1118','101922','1a2733','69b58d','95aabf','c3d3e1','e47c96',
            '7bd4d7','e7c589','a8becd','b7c9d7','8fa6ba','ffffff','000000','4a303c','603849','362731',
            '36242d','aa506a','78d7db','e2cfa6','302b23','80d7cf','ef9eb3','7e97ac','9eb0c2','83ecfa']
reserved = [int(color[i:i+2], 16) for color in semantic for i in (0, 2, 4)]
palette = Image.new('P', (1, 1))
palette.putpalette((sample_palette + reserved + [0] * 768)[:768])
frames = []
for item in manifest['frames']:
    with Image.open(args.frames / item['file']) as im:
        frames.append(im.convert('RGB').quantize(palette=palette, dither=Image.Dither.NONE))
args.output.parent.mkdir(parents=True, exist_ok=True)
frames[0].save(args.output, save_all=True, append_images=frames[1:], duration=[i['durationMs'] for i in manifest['frames']], loop=0, optimize=True, disposal=1)
with Image.open(args.output) as gif:
    durations = []
    for i in range(gif.n_frames):
        gif.seek(i)
        durations.append(gif.info['duration'])
    assert gif.size == (1440, 1060)
    assert gif.info.get('loop') == 0
    assert abs(sum(durations) - sum(i['durationMs'] for i in manifest['frames'])) < 100
    print(json.dumps({'file': str(args.output), 'frames': gif.n_frames, 'size': gif.size, 'duration_seconds': sum(durations)/1000, 'megabytes': round(args.output.stat().st_size/1048576, 2), 'runs': len(manifest['runs'])}))
