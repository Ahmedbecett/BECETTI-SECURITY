#!/usr/bin/env python3
"""
Build the Microsoft Store trailer (1920x1080 H.264) for BECETTI SECURITY.

This is a *brand motion* trailer assembled from the app's own real artwork
(mascot + wordmark) — it is NOT a screen recording, and it makes no claim of
showing the UI. Microsoft accepts .mp4/.mov at 1920x1080.

Frames are rendered with PIL and piped to ffmpeg (via imageio-ffmpeg's static
binary, so no system ffmpeg is needed). Narration comes from
store/trailer/vo/*.mp3.

Run:  .venv-art/bin/python scripts/store-trailer.py
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
VO = ROOT / "store" / "trailer" / "vo"
OUT = ROOT / "store" / "trailer" / "BECETTI-SECURITY-trailer-1920x1080.mp4"

spec = importlib.util.spec_from_file_location("sa", ROOT / "scripts" / "store-art.py")
sa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sa)

W, H = 1920, 1080
FPS = 30
PW, PH = int(W * 1.12), int(H * 1.12)   # plate resolution, cropped for Ken Burns
XF = 0.55                                # crossfade seconds

CYAN, EMERALD, WHITE = sa.CYAN, sa.EMERALD, sa.WHITE
MUTED = (140, 158, 180)
BG_TOP, BG_BOTTOM = (3, 6, 13), (9, 18, 32)


# --------------------------------------------------------------------------- #
# plates
# --------------------------------------------------------------------------- #
def _backdrop(with_arcs=True):
    img = sa.vgrad((PW, PH), BG_TOP, BG_BOTTOM)
    img = sa.screen(img, sa.radial((PW, PH), (PW * 0.50, PH * 0.50), PW * 0.66, PH * 0.95, CYAN, 0.30))
    img = sa.screen(img, sa.radial((PW, PH), (PW * 0.50, PH * 0.50), PW * 0.30, PH * 0.42, sa.CYAN_SOFT, 0.22))
    img = img.convert("RGBA")
    img.alpha_composite(sa.grid((PW, PH), 118, CYAN, 7))
    if with_arcs:
        img.alpha_composite(sa.shield_watermark((PW, PH), (PW * 0.50, PH * 0.52), PW * 0.94, EMERALD, 30, 3))
    return img


def _mascot(img, side, scale=0.88):
    m = sa.load_mascot(int(PH * scale))
    cx = PW * (0.755 if side == "right" else 0.245)
    sa.paste_glowing(img, m, (cx, PH * 0.52), CYAN, 78, 112)


def _heading(img, text, cx, top, max_w, color=WHITE, start=150, track=0.055):
    f, t = sa.fit_font(text, max_w, track, start)
    sa.tracked_text(img, (cx, top), text, f, color, tracking=t)
    return f, t


def plate_title():
    img = _backdrop()
    sa.paste_glowing(img, sa.load_mascot(int(PH * 0.44)), (PW * 0.5, PH * 0.86), CYAN, 70, 110)
    f1, t1 = sa.fit_font("BECETTI", PW * 0.80, 0.055, 250)
    f2, t2 = sa.fit_font("SECURITY", PW * 0.80, 0.075, 250)
    sa.tracked_text(img, (PW * 0.5, PH * 0.16), "BECETTI", f1, WHITE, tracking=t1)
    sa.tracked_text(img, (PW * 0.5, PH * 0.16 + 272), "SECURITY", f2, CYAN, tracking=t2)
    d = ImageDraw.Draw(img)
    d.line([(PW * 0.5 - 90, PH * 0.16 + 560), (PW * 0.5 + 90, PH * 0.16 + 560)],
           fill=EMERALD + (220,), width=4)
    return img


def plate_scene(heading, sub, side, accent=CYAN, eyebrow=None):
    img = _backdrop()
    _mascot(img, side)
    cx = PW * (0.285 if side == "right" else 0.70)
    max_w = PW * (0.44 if side == "right" else 0.42)
    top = PH * 0.33
    if eyebrow:
        fe, te = sa.fit_font(eyebrow, max_w * 0.9, 0.22, 34)
        sa.tracked_text(img, (cx, top - 66), eyebrow, fe, accent, tracking=te)
        top += 10
    f, _ = _heading(img, heading, cx, top, max_w, WHITE, 140, 0.045)
    fs, ts = sa.fit_font(sub, max_w, 0.02, 46)
    sa.tracked_text(img, (cx, top + 200), sub, fs, MUTED, tracking=ts)
    return img


def plate_end():
    img = _backdrop()
    sa.paste_glowing(img, sa.load_mascot(int(PH * 0.38)), (PW * 0.5, PH * 0.84), CYAN, 70, 108)
    f1, t1 = sa.fit_font("BECETTI", PW * 0.62, 0.055, 180)
    f2, t2 = sa.fit_font("SECURITY", PW * 0.62, 0.075, 180)
    sa.tracked_text(img, (PW * 0.5, PH * 0.10), "BECETTI", f1, WHITE, tracking=t1)
    sa.tracked_text(img, (PW * 0.5, PH * 0.10 + 196), "SECURITY", f2, CYAN, tracking=t2)
    fs, ts = sa.fit_font("No simulated security, ever.", PW * 0.72, 0.03, 54)
    sa.tracked_text(img, (PW * 0.5, PH * 0.475), "No simulated security, ever.", fs, WHITE, tracking=ts)
    return img


# --------------------------------------------------------------------------- #
# timeline
# --------------------------------------------------------------------------- #
SCENES = [
    (0.00, 2.60, "title"),
    (2.60, 4.00, "s2"),
    (6.60, 4.40, "s3"),
    (11.00, 3.80, "s4"),
    (14.80, 4.10, "s5"),
    (18.90, 5.30, "s6"),
    (24.20, 3.70, "s7"),
    (27.90, 3.60, "end"),
]
TOTAL = sum(d for _, d, _ in SCENES)


def build_plates():
    return {
        "title": plate_title(),
        "s2": plate_scene("One dashboard", "Everything protecting your PC, in one place.", "right", CYAN, "01 — OVERVIEW"),
        "s3": plate_scene("Defender + YARA", "Two real engines, scanning together.", "left", EMERALD, "02 — ENGINE"),
        "s4": plate_scene("Live threat intel", "Feodo Tracker  ·  URLhaus  ·  MalwareBazaar", "right", CYAN, "03 — INTELLIGENCE"),
        "s5": plate_scene("MITRE ATT&CK", "24 enterprise techniques, tagged automatically.", "left", EMERALD, "04 — COVERAGE"),
        "s6": plate_scene("EDR & hardening", "Persistence  ·  Ransomware  ·  Forensics", "right", CYAN, "05 — DEFENSE"),
        "s7": plate_scene("Ask BECETTI AI", "Answers built from verified data only.", "left", sa.CYAN_SOFT, "06 — COPILOT"),
        "end": plate_end(),
    }


def render(plate, p):
    zoom = 1.0 + 0.065 * p
    cw, ch = int(PW / zoom), int(PH / zoom)
    x = (PW - cw) // 2
    y = int((PH - ch) * 0.45)
    return plate.crop((x, y, x + cw, y + ch)).resize((W, H), Image.LANCZOS)


def ease(v):
    return v * v * (3 - 2 * v)


def main():
    print("Building plates...")
    plates = build_plates()

    n_frames = int(round(TOTAL * FPS))
    ff = __import__("imageio_ffmpeg").get_ffmpeg_exe()
    silent = OUT.with_name("_silent.mp4")

    cmd = [
        ff, "-y", "-f", "rawvideo", "-pix_fmt", "rgb24",
        "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
        "-c:v", "libx264", "-preset", "medium", "-crf", "19",
        "-pix_fmt", "yuv420p", "-movflags", "+faststart",
        str(silent),
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for i in range(n_frames):
        t = i / FPS
        idx = 0
        for k, (st, du, _) in enumerate(SCENES):
            if t >= st:
                idx = k
        st, du, key = SCENES[idx]
        p = (t - st) / du

        frame = render(plates[key], p)

        # crossfade into the next scene
        if idx + 1 < len(SCENES):
            cut = 1.0 - XF / du
            if p > cut:
                q = ease((p - cut) / (XF / du))
                nxt = render(plates[SCENES[idx + 1][2]], 0.0)
                frame = Image.blend(frame, nxt, q)

        frame = frame.convert("RGBA")
        d = ImageDraw.Draw(frame)

        # bottom progress line
        d.rectangle([0, H - 4, W, H], fill=(6, 14, 26, 255))
        d.rectangle([0, H - 4, int(W * (t / TOTAL)), H], fill=EMERALD + (235,))

        # fade in / out
        a = 1.0
        if t < 0.5:
            a = ease(t / 0.5)
        elif t > TOTAL - 0.9:
            a = ease(max(0.0, (TOTAL - t) / 0.9))
        if a < 1.0:
            black = Image.new("RGBA", (W, H), (0, 0, 0, 255))
            frame = Image.blend(black, frame, a)

        proc.stdin.write(frame.convert("RGB").tobytes())
        if i % 90 == 0:
            print(f"  frame {i}/{n_frames}  t={t:5.2f}s")

    proc.stdin.close()
    proc.wait()
    print("silent video ->", silent, silent.stat().st_size // 1024, "KB")

    # ---- mux narration -------------------------------------------------- #
    inputs, filters, labels = [], [], []
    offsets = {1: 0.35, 2: 2.95, 3: 6.95, 4: 11.35, 5: 15.15, 6: 19.25, 7: 24.55, 8: 28.25}
    for n in range(1, 9):
        f = VO / f"{n:02d}.mp3"
        if not f.exists():
            raise SystemExit(f"missing {f}")
        inputs += ["-i", str(f)]
        ms = int(offsets[n] * 1000)
        filters.append(f"[{n}:a]adelay={ms}|{ms},volume=1.0[a{n}]")
        labels.append(f"[a{n}]")

    fc = ";".join(filters) + ";" + "".join(labels) + \
         f"amix=inputs={len(labels)}:normalize=0,alimiter=limit=0.95,atrim=0:{TOTAL}[a]"

    cmd2 = [ff, "-y", "-i", str(silent)] + inputs + [
        "-filter_complex", fc, "-map", "0:v", "-map", "[a]",
        "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-shortest", str(OUT),
    ]
    subprocess.run(cmd2, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    silent.unlink(missing_ok=True)
    print("trailer ->", OUT, OUT.stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main()
