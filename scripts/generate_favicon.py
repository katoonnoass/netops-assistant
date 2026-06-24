from PIL import Image, ImageDraw
import struct, io

COLORS = {"bg": (12, 14, 20), "bar1": (212, 143, 26), "bar2": (245, 166, 53), "bar3": (247, 183, 49)}

def create_svg():
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="7" fill="#0c0e14"/>
  <rect x="9" y="18" width="4" height="9" rx="2" fill="#d48f1a"/>
  <rect x="14" y="11" width="4" height="16" rx="2" fill="#f5a635"/>
  <rect x="19" y="6" width="4" height="21" rx="2" fill="#f7b731"/>
</svg>"""

def create_ico(size=32):
    im = Image.new("RGBA", (size, size), (12, 14, 20, 255))
    draw = ImageDraw.Draw(im)
    w, h = size, size
    r = max(1, int(w * 0.22))
    bar_w = max(2, int(w * 0.12))
    gap = max(1, int(w * 0.06))
    base_y = int(h * 0.62)
    x1 = int(w * 0.28)
    heights = [int(h * 0.28), int(h * 0.5), int(h * 0.66)]
    colors = [(212, 143, 26, 255), (245, 166, 53, 255), (247, 183, 49, 255)]
    for i, (bar_h, col) in enumerate(zip(heights, colors)):
        bx = x1 + i * (bar_w + gap)
        by = base_y - bar_h
        draw.rounded_rectangle([bx, by, bx + bar_w, base_y], radius=r, fill=col)
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    png_data = buf.getvalue()
    ico_buf = io.BytesIO()
    ico_buf.write(struct.pack("<HHH", 0, 1, 1))
    ico_buf.write(struct.pack("<BBBBHHII", size if size < 256 else 0, size if size < 256 else 0, 0, 0, 1, 32, len(png_data), 22))
    ico_buf.write(png_data)
    return ico_buf.getvalue()

if __name__ == "__main__":
    svg = create_svg()
    with open("static/favicon.svg", "w", encoding="utf-8") as f:
        f.write(svg)
    ico = create_ico(32)
    with open("static/favicon.ico", "wb") as f:
        f.write(ico)
    ico_16 = create_ico(16)
    with open("static/favicon-16x16.ico", "wb") as f:
        f.write(ico_16)
    print("Favicons generated successfully")
