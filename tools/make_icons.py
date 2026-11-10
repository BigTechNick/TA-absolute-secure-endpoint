"""Draws the add-on's icons (a laptop with a location pin): static/appIcon*.png."""
import os
import sys
from PIL import Image, ImageDraw


def draw(size, background):
    s = size * 8
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    fg = (255, 255, 255, 255)
    if background:
        d.rounded_rectangle([0, 0, s - 1, s - 1], radius=s // 6, fill=(31, 78, 121, 255))
    else:
        fg = (31, 78, 121, 255)
    w = max(2, s // 22)
    # laptop screen and base
    d.rounded_rectangle([s * 0.20, s * 0.30, s * 0.80, s * 0.68], radius=s // 40, outline=fg, width=w)
    d.polygon([(s * 0.10, s * 0.74), (s * 0.90, s * 0.74), (s * 0.84, s * 0.80), (s * 0.16, s * 0.80)], fill=fg)
    # location pin on the screen
    cx, cy, r = s * 0.50, s * 0.44, s * 0.085
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fg)
    d.polygon([(cx - r * 0.85, cy + r * 0.45), (cx + r * 0.85, cy + r * 0.45), (cx, cy + r * 2.1)], fill=fg)
    hole = r * 0.42
    d.ellipse([cx - hole, cy - hole, cx + hole, cy + hole], fill=(31, 78, 121, 255) if background else (0, 0, 0, 0))
    return img.resize((size, size), Image.LANCZOS)


def main(folder):
    os.makedirs(folder, exist_ok=True)
    for name, size, bg in (("appIcon.png", 36, True), ("appIcon_2x.png", 72, True),
                           ("appIconAlt.png", 36, False), ("appIconAlt_2x.png", 72, False)):
        draw(size, bg).save(os.path.join(folder, name), optimize=True)


if __name__ == "__main__":
    main(sys.argv[1])
