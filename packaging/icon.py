"""Draw the application's vector-like icon from primitives."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def main():
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((4, 4, 251, 251), radius=55, fill='#101b2e', outline='#4074ad', width=6)
    draw.rounded_rectangle((18, 18, 237, 237), radius=45, outline='#233b59', width=2)
    draw.line([(35, 158), (75, 158), (93, 133), (112, 179), (135, 99),
               (153, 149), (172, 149), (190, 124), (222, 124)], fill='#57b8ff', width=12, joint='curve')
    draw.ellipse((123, 87, 147, 111), fill='#a9e4ff')
    font_path = Path('C:/Windows/Fonts/seguisb.ttf')
    font = ImageFont.truetype(str(font_path), 65) if font_path.exists() else ImageFont.load_default()
    draw.text((48, 33), 'L2', fill='#f0f8ff', font=font)
    out = Path(__file__).with_name('L2PacketMonitor.ico')
    image.save(out, format='ICO', sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(out)


if __name__ == '__main__':
    main()
