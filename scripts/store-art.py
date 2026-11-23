#!/usr/bin/env python3
"""
Generate the Microsoft Store *listing* artwork for BECETTI SECURITY.

Only brand / marketing art is produced here (poster art, box art, super hero art,
app tile icons). Store SCREENSHOTS are deliberately NOT generated: Partner Center
requires real captures of the running app, and this project forbids fabricated
imagery. See store/screenshots-shotlist.md for the capture plan.

Everything is derived from real in-repo brand assets:
  - src/Becetti.Security.App/Assets/RobotMascotHero.png   (the app mascot)
  - src/Becetti.Security.App/Assets/Square310x310Logo.png (the real app tile)
so the artwork stays faithful to what ships in the package.

RobotMascotHero.png is an opaque RGB file whose "transparency" is a baked-in
Photoshop checkerboard (#393939 / #595959, 26px cells). This script rebuilds a
true alpha channel for it (see cutout_mascot) instead of shipping the checker.

Output: store/art/*.png at the exact pixel sizes Partner Center requires.
Run:  .venv-art/bin/python scripts/store-art.py
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "src" / "Becetti.Security.App" / "Assets"
OUT = ROOT / "store" / "art"
CACHE = ROOT / ".art-cache"

# Brand palette (taken from src/Becetti.Security.App/Assets/logo.svg)
BG_TOP = (4, 7, 14)
BG_BOTTOM = (9, 18, 32)
CYAN = (56, 189, 248)
CYAN_SOFT = (34, 211, 238)
EMERALD = (16, 185, 129)
WHITE = (248, 250, 252)
MUTED = (125, 145, 170)

FONT_DIR = (Path(__file__).resolve().parent.parent / ".venv-art" / "lib" /
            "python3.11" / "site-packages" / "matplotlib" / "mpl-data" / "fonts" / "ttf")
FONT_BOLD = str(FONT_DIR / "DejaVuSans-Bold.ttf")
FONT_REG = str(FONT_DIR / "DejaVuSans.ttf")

CHECKER_DARK = 57.0   # #393939
CHECKER_LIGHT = 89.0  # #595959


# --------------------------------------------------------------------------- #
# background primitives (all additive / "screen", so the base stays dark)
# --------------------------------------------------------------------------- #
def vgrad(size, top, bottom) -> Image.Image:
    w, h = size
    col = Image.new("RGB", (1, h))
    px = col.load()
    for y in range(h):
        t = (y / max(h - 1, 1)) ** 0.9
        px[0, y] = tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
    return col.resize((w, h), Image.BICUBIC)


def radial(size, center, rx, ry, color, intensity) -> Image.Image:
    """Black RGB image holding one soft coloured light. Blend with screen()."""
    w, h = size
    small = 256
    sw, sh = small, max(1, int(round(small * h / w)))
    yy, xx = np.mgrid[0:sh, 0:sw]
    cx, cy = center[0] / w * sw, center[1] / h * sh
    rx_s, ry_s = max(rx / w * sw, 1.0), max(ry / h * sh, 1.0)
    d = np.sqrt(((xx - cx) / rx_s) ** 2 + ((yy - cy) / ry_s) ** 2)
    falloff = np.clip(1.0 - d, 0.0, 1.0) ** 2.4
    arr = np.zeros((sh, sw, 3), dtype=np.float32)
    for i in range(3):
        arr[:, :, i] = falloff * color[i] * intensity
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGB")
    return img.resize((w, h), Image.BICUBIC)


def screen(a: Image.Image, b: Image.Image) -> Image.Image:
    aa = np.asarray(a.convert("RGB"), np.int32)
    bb = np.asarray(b.convert("RGB"), np.int32)
    return Image.fromarray(
        (255 - (255 - aa) * (255 - bb) // 255).astype(np.uint8), "RGB"
    )


def grid(size, step, color=CYAN, alpha=14) -> Image.Image:
    w, h = size
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for x in range(0, w, step):
        d.line([(x, 0), (x, h)], fill=color + (alpha,), width=1)
    for y in range(0, h, step):
        d.line([(0, y), (w, y)], fill=color + (alpha,), width=1)
    return layer


def bezier(p0, p1, p2, p3, n=64):
    out = []
    for i in range(n + 1):
        t, mt = i / n, 1 - i / n
        out.append((
            mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0],
            mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1],
        ))
    return out


def shield_points(s: float):
    """The exact shield outline from Assets/logo.svg, scaled to `s` px."""
    k = s / 256.0
    pts = [(128, 28), (196, 52), (196, 128)]
    pts += bezier((196, 128), (196, 176), (168, 208), (128, 228))
    pts += bezier((128, 228), (88, 208), (60, 176), (60, 128))
    pts += [(60, 128), (60, 52), (128, 28)]
    return [(x * k, y * k) for x, y in pts]


def shield_watermark(size, center, s, color=CYAN, alpha=26, width=3) -> Image.Image:
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    pts = [(center[0] - s / 2 + x, center[1] - s / 2 + y) for x, y in shield_points(s)]
    d.line(pts + [pts[0]], fill=color + (alpha,), width=width, joint="curve")
    k = s / 256.0
    chk = [(center[0] - s / 2 + x * k, center[1] - s / 2 + y * k)
           for x, y in ((96, 128), (118, 150), (162, 100))]
    d.line(chk, fill=color + (alpha,), width=width * 2, joint="curve")
    for p in chk:
        d.ellipse([p[0] - width, p[1] - width, p[0] + width, p[1] + width],
                  fill=color + (alpha,))
    return layer


def tracked_text(canvas, xy, text, font, fill, tracking=0.0):
    widths = [font.getlength(c) for c in text]
    total = sum(widths) + tracking * (len(text) - 1)
    x = xy[0] - total / 2
    d = ImageDraw.Draw(canvas)
    for ch, w in zip(text, widths):
        d.text((x, xy[1]), ch, font=font, fill=fill)
        x += w + tracking
    return total


# --------------------------------------------------------------------------- #
# mascot: rebuild a real alpha channel over the baked-in checkerboard
# --------------------------------------------------------------------------- #
def cutout_mascot() -> Image.Image:
    """Rebuild a true alpha channel for RobotMascotHero.png.

    The source has NO alpha: its "transparency" is a baked-in Photoshop
    checkerboard (#393939 / #595959, 26px cells) and the mascot's neon glow is
    additively blended into that checker. Colour-keying therefore cannot work
    (the glow is bright, so it reads as "foreground" and drags the checker
    pattern with it).

    Instead the silhouette is segmented geometrically: the checkerboard has
    weak edges (32 levels), the mascot has strong ones, and the glow has no
    edge at all. So flood-filling from the border across "no strong edge"
    yields exactly the background+glow region, and its complement is the
    solid mascot. The glow itself is re-created synthetically at composite
    time (paste_glowing), so it comes out clean instead of checkered.
    """
    CACHE.mkdir(parents=True, exist_ok=True)
    cached = CACHE / "mascot-cutout.png"
    if cached.exists():
        return Image.open(cached).convert("RGBA")

    from scipy import ndimage

    src = Image.open(ASSETS / "RobotMascotHero.png").convert("RGB")
    arr = np.asarray(src, dtype=np.float32)

    gray = arr.mean(axis=2)
    gy, gx = np.gradient(gray)
    grad = np.hypot(gx, gy)

    barrier = grad > 18.0          # checker cell seams are ~32 apart => below this
    barrier = ndimage.binary_dilation(barrier, iterations=2)

    free = ~barrier
    labels, _ = ndimage.label(free)
    border = set(labels[0, :]) | set(labels[-1, :]) | set(labels[:, 0]) | set(labels[:, -1])
    border.discard(0)
    background = np.isin(labels, list(border))

    body = ~background
    body = ndimage.binary_closing(body, structure=np.ones((5, 5)))
    body = ndimage.binary_fill_holes(body)
    body = ndimage.binary_opening(body, structure=np.ones((3, 3)))

    # The source art carries a dotted "circuit" texture in its background; the
    # gradient barrier isolates those dots into their own tiny components.
    # Keep only the mascot itself.
    labels, n = ndimage.label(body)
    if n > 1:
        sizes = ndimage.sum_labels(body, labels, range(1, n + 1))
        body = labels == (int(np.argmax(sizes)) + 1)

    body = ndimage.binary_erosion(body, iterations=1)   # drop the grey fringe
    body = ndimage.binary_dilation(body, iterations=1)

    mask = Image.fromarray((body * 255).astype(np.uint8), "L")
    mask = mask.filter(ImageFilter.GaussianBlur(1.1))

    out = src.convert("RGBA")
    out.putalpha(mask)
    out.save(cached)
    return out


def load_mascot(target_h: int) -> Image.Image:
    src = cutout_mascot()
    ratio = target_h / src.height
    return src.resize((max(1, int(src.width * ratio)), target_h), Image.LANCZOS)


def paste_glowing(base, sprite, center, glow_color=CYAN, glow_radius=90, glow_alpha=110):
    w, h = base.size
    x = int(center[0] - sprite.width / 2)
    y = int(center[1] - sprite.height / 2)

    bloom = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    a = sprite.split()[-1]
    tinted = Image.new("RGBA", sprite.size, glow_color + (0,))
    tinted.putalpha(a)
    bloom.paste(tinted, (x, y), tinted)
    bloom = bloom.filter(ImageFilter.GaussianBlur(glow_radius))
    bloom.putalpha(bloom.getchannel("A").point(lambda v: int(v * glow_alpha / 255)))
    base.alpha_composite(bloom)
    base.alpha_composite(sprite, (x, y))


def save(img: Image.Image, name: str):
    OUT.mkdir(parents=True, exist_ok=True)
    p = OUT / name
    img.convert("RGB").save(p, "PNG", optimize=True)
    print(f"  {name:30s} {img.width}x{img.height}  {p.stat().st_size // 1024} KB")


# --------------------------------------------------------------------------- #
# 9:16 poster art  (1440x2160 and 720x1080)
# --------------------------------------------------------------------------- #
def poster(w: int, h: int) -> Image.Image:
    k = w / 1440.0
    img = vgrad((w, h), BG_TOP, BG_BOTTOM)
    img = screen(img, radial((w, h), (w * 0.5, h * 0.44), w * 0.78, h * 0.62, CYAN, 0.30))
    img = screen(img, radial((w, h), (w * 0.5, h * 0.45), w * 0.34, h * 0.30, CYAN_SOFT, 0.26))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), max(24, int(120 * k)), CYAN, 7))
    img.alpha_composite(shield_watermark((w, h), (w * 0.5, h * 0.44), w * 1.02, EMERALD, 30, max(2, int(3 * k))))

    ring = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(ring)
    cx, cy = w * 0.5, h * 0.44
    for i, r in enumerate((0.31, 0.41)):
        rr = w * r
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=CYAN + (30 - i * 10,), width=max(2, int(2 * k)))
    img.alpha_composite(ring)

    paste_glowing(img, load_mascot(int(h * 0.50)), (w * 0.5, h * 0.445), CYAN, int(60 * k), 100)

    f1 = ImageFont.truetype(FONT_BOLD, int(148 * k))
    f2 = ImageFont.truetype(FONT_BOLD, int(148 * k))
    f3 = ImageFont.truetype(FONT_REG, int(38 * k))

    y1 = h * 0.755
    tracked_text(img, (w * 0.5, y1), "BECETTI", f1, WHITE, tracking=10 * k)
    tracked_text(img, (w * 0.5, y1 + 170 * k), "SECURITY", f2, CYAN, tracking=16 * k)

    d = ImageDraw.Draw(img)
    d.line([(w * 0.5 - 60 * k, y1 + 368 * k), (w * 0.5 + 60 * k, y1 + 368 * k)],
           fill=EMERALD + (210,), width=max(2, int(2 * k)))
    tracked_text(img, (w * 0.5, y1 + 396 * k), "WINDOWS 10  ·  WINDOWS 11", f3, MUTED, tracking=6 * k)
    return img


# --------------------------------------------------------------------------- #
# 1:1 box art  (2160x2160 and 1080x1080)
# --------------------------------------------------------------------------- #
def boxart(w: int, h: int) -> Image.Image:
    k = w / 2160.0
    img = vgrad((w, h), BG_TOP, BG_BOTTOM)
    img = screen(img, radial((w, h), (w * 0.5, h * 0.44), w * 0.62, w * 0.62, CYAN, 0.30))
    img = screen(img, radial((w, h), (w * 0.5, h * 0.44), w * 0.28, w * 0.28, CYAN_SOFT, 0.24))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), int(150 * k), CYAN, 7))
    img.alpha_composite(shield_watermark((w, h), (w * 0.5, h * 0.43), w * 0.88, EMERALD, 30, max(2, int(4 * k))))

    paste_glowing(img, load_mascot(int(h * 0.54)), (w * 0.5, h * 0.43), CYAN, int(70 * k), 105)

    f1 = ImageFont.truetype(FONT_BOLD, int(186 * k))
    f2 = ImageFont.truetype(FONT_BOLD, int(186 * k))

    y1 = h * 0.735
    tracked_text(img, (w * 0.5, y1), "BECETTI", f1, WHITE, tracking=12 * k)
    tracked_text(img, (w * 0.5, y1 + 208 * k), "SECURITY", f2, CYAN, tracking=20 * k)

    d = ImageDraw.Draw(img)
    d.line([(w * 0.5 - 80 * k, y1 + 424 * k), (w * 0.5 + 80 * k, y1 + 424 * k)],
           fill=EMERALD + (210,), width=max(2, int(3 * k)))
    return img


# --------------------------------------------------------------------------- #
# 16:9 super hero art — MUST NOT contain the product title
# --------------------------------------------------------------------------- #
def superhero(w: int, h: int) -> Image.Image:
    k = w / 3840.0
    img = vgrad((w, h), (2, 5, 11), (8, 18, 33))
    img = screen(img, radial((w, h), (w * 0.74, h * 0.50), w * 0.34, h * 0.85, CYAN, 0.34))
    img = screen(img, radial((w, h), (w * 0.14, h * 0.52), w * 0.24, h * 0.62, EMERALD, 0.16))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), int(160 * k), CYAN, 6))

    arcs = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(arcs)
    cx, cy = w * 0.085, h * 0.50
    for i in range(5):
        r = w * (0.15 + i * 0.085)
        d.arc([cx - r, cy - r, cx + r, cy + r], start=-55, end=55,
              fill=(CYAN if i % 2 == 0 else EMERALD) + (80 - i * 11,),
              width=max(2, int(4 * k)))
    img.alpha_composite(arcs)
    img.alpha_composite(shield_watermark((w, h), (w * 0.13, h * 0.50), w * 0.26, CYAN, 46, max(2, int(3 * k))))

    paste_glowing(img, load_mascot(int(h * 0.86)), (w * 0.735, h * 0.52), CYAN, int(100 * k), 120)
    return img


def fit_font(text: str, max_w: float, tracking_ratio: float, start: float):
    """Largest DejaVu Bold size (plus letter-spacing) that fits `max_w`."""
    size = start
    while size > 8:
        f = ImageFont.truetype(FONT_BOLD, int(size))
        width = sum(f.getlength(c) for c in text) + tracking_ratio * size * (len(text) - 1)
        if width <= max_w:
            return f, tracking_ratio * size
        size -= 2
    return ImageFont.truetype(FONT_BOLD, 8), 0.0


# --------------------------------------------------------------------------- #
# Xbox: branded key art 584x800 — title MUST sit in the top 3/4
# --------------------------------------------------------------------------- #
def branded_keyart(w: int = 584, h: int = 800) -> Image.Image:
    k = w / 584.0
    img = vgrad((w, h), BG_TOP, BG_BOTTOM)
    img = screen(img, radial((w, h), (w * 0.5, h * 0.52), w * 0.72, h * 0.55, CYAN, 0.34))
    img = screen(img, radial((w, h), (w * 0.5, h * 0.52), w * 0.34, h * 0.30, CYAN_SOFT, 0.26))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), int(74 * k), CYAN, 8))
    img.alpha_composite(shield_watermark((w, h), (w * 0.5, h * 0.54), w * 1.10, EMERALD, 34, max(2, int(2 * k))))

    paste_glowing(img, load_mascot(int(h * 0.56)), (w * 0.5, h * 0.53), CYAN, int(34 * k), 105)

    # wordmark — well inside the top 3/4 (y < 0.75h)
    f1, t1 = fit_font("BECETTI", w * 0.84, 0.055, 74 * k)
    f2, t2 = fit_font("SECURITY", w * 0.84, 0.075, 74 * k)
    y1 = h * 0.085
    tracked_text(img, (w * 0.5, y1), "BECETTI", f1, WHITE, tracking=t1)
    tracked_text(img, (w * 0.5, y1 + 92 * k), "SECURITY", f2, CYAN, tracking=t2)

    d = ImageDraw.Draw(img)
    d.line([(w * 0.5 - 44 * k, y1 + 186 * k), (w * 0.5 + 44 * k, y1 + 186 * k)],
           fill=EMERALD + (210,), width=max(2, int(2 * k)))

    # bottom 1/4 is the only place a text overlay is allowed
    f3, t3 = fit_font("WINDOWS 10  ·  WINDOWS 11", w * 0.80, 0.14, 19 * k)
    tracked_text(img, (w * 0.5, h * 0.905), "WINDOWS 10  ·  WINDOWS 11", f3, MUTED, tracking=t3)
    return img


# --------------------------------------------------------------------------- #
# Xbox: titled hero art 1920x1080 — title MUST sit in the top 3/4
# --------------------------------------------------------------------------- #
def titled_heroart(w: int = 1920, h: int = 1080) -> Image.Image:
    k = w / 1920.0
    img = vgrad((w, h), (2, 5, 11), (8, 18, 33))
    img = screen(img, radial((w, h), (w * 0.73, h * 0.50), w * 0.36, h * 0.85, CYAN, 0.34))
    img = screen(img, radial((w, h), (w * 0.24, h * 0.42), w * 0.30, h * 0.55, CYAN_SOFT, 0.18))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), int(96 * k), CYAN, 7))
    img.alpha_composite(shield_watermark((w, h), (w * 0.26, h * 0.46), w * 0.30, EMERALD, 40, max(2, int(3 * k))))

    paste_glowing(img, load_mascot(int(h * 0.84)), (w * 0.735, h * 0.52), CYAN, int(56 * k), 115)

    # title inside the top 3/4 (y < 0.75h = 810)
    f1, t1 = fit_font("BECETTI", w * 0.42, 0.055, 132 * k)
    f2, t2 = fit_font("SECURITY", w * 0.42, 0.075, 132 * k)
    y1 = h * 0.33
    tracked_text(img, (w * 0.26, y1), "BECETTI", f1, WHITE, tracking=t1)
    tracked_text(img, (w * 0.26, y1 + 152 * k), "SECURITY", f2, CYAN, tracking=t2)

    d = ImageDraw.Draw(img)
    d.line([(w * 0.26 - 70 * k, y1 + 300 * k), (w * 0.26 + 70 * k, y1 + 300 * k)],
           fill=EMERALD + (210,), width=max(2, int(3 * k)))
    return img


# --------------------------------------------------------------------------- #
# Xbox: featured promotional square art 1080x1080 — must NOT contain the title
# --------------------------------------------------------------------------- #
def featured_square(w: int = 1080, h: int = 1080) -> Image.Image:
    k = w / 1080.0
    img = vgrad((w, h), BG_TOP, BG_BOTTOM)
    img = screen(img, radial((w, h), (w * 0.5, h * 0.48), w * 0.66, w * 0.66, CYAN, 0.32))
    img = screen(img, radial((w, h), (w * 0.5, h * 0.48), w * 0.30, w * 0.30, CYAN_SOFT, 0.26))
    img = img.convert("RGBA")
    img.alpha_composite(grid((w, h), int(90 * k), CYAN, 7))
    img.alpha_composite(shield_watermark((w, h), (w * 0.5, h * 0.48), w * 0.98, EMERALD, 32, max(2, int(3 * k))))

    ring = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(ring)
    cx, cy = w * 0.5, h * 0.48
    for i, r in enumerate((0.36, 0.46)):
        rr = w * r
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=CYAN + (28 - i * 9,), width=max(2, int(2 * k)))
    img.alpha_composite(ring)

    paste_glowing(img, load_mascot(int(h * 0.72)), (w * 0.5, h * 0.48), CYAN, int(48 * k), 110)
    return img


def app_icons():
    src = Image.open(ASSETS / "Square310x310Logo.png").convert("RGBA")
    for size in (300, 150, 71):
        save(src.resize((size, size), Image.LANCZOS), f"appicon-{size}x{size}.png")


def main():
    print("Generating Store listing artwork ->", OUT)
    save(poster(1440, 2160), "poster-1440x2160.png")
    save(poster(720, 1080), "poster-720x1080.png")
    save(boxart(2160, 2160), "boxart-2160x2160.png")
    save(boxart(1080, 1080), "boxart-1080x1080.png")
    save(superhero(3840, 2160), "superhero-3840x2160.png")
    save(superhero(1920, 1080), "superhero-1920x1080.png")
    save(branded_keyart(584, 800), "xbox-branded-keyart-584x800.png")
    save(titled_heroart(1920, 1080), "xbox-titled-heroart-1920x1080.png")
    save(featured_square(1080, 1080), "xbox-featured-square-1080x1080.png")
    app_icons()
    print("done.")


if __name__ == "__main__":
    main()
