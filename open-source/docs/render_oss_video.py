#!/usr/bin/env python3
"""WraithWall OSS launch video — real site screenshots synced to narration + ambient score."""
from __future__ import annotations

import math
import subprocess
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
FPS = 24
DURATION = 48.0
FRAMES = 0
OUT_DIR = Path("/tmp/ww-oss-frames")
OUT_MP4 = Path("/tmp/wraithwall-oss-launch.mp4")
AUDIO_DIR = Path("/tmp/ww-oss-audio")
DOCS_DIR = Path(__file__).resolve().parent
SCREEN_DIR = DOCS_DIR / "real-screens"
STATIC_DIR = Path("/home/deploy/ezmcyber/static/img/oss-launch")

# Nigerian English — natural young male African voice (alt: en-KE-ChilembaNeural, en-ZA-LukeNeural)
TTS_VOICE = "en-NG-AbeoNeural"

SIGNAL = (196, 26, 26)
INK = (26, 26, 26)
CAPTION_BG = (8, 9, 11, 210)


@dataclass
class Beat:
    text: str
    image: str
    zoom_start: float = 1.0
    zoom_end: float = 1.08
    pan_x: float = 0.0
    pan_y: float = 0.0


# Narration lines mapped to real pages the viewer should see while hearing them.
BEATS = [
    Beat("Introducing WraithWall.", "landing-hero.png", 1.0, 1.05),
    Beat("Deception infrastructure that fights back.", "landing-hero.png", 1.05, 1.12, pan_y=-0.02),
    Beat(
        "Built for security operators who need active defense, not another dashboard demo.",
        "architecture.png",
        1.0,
        1.1,
    ),
    Beat(
        "Live Cowrie honeypots capture real attacker sessions.",
        "landing-terminal.png",
        1.0,
        1.1,
        pan_y=-0.04,
    ),
    Beat(
        "Canary tokens detect supply-chain intrusions before they spread.",
        "launch.png",
        1.0,
        1.08,
    ),
    Beat("BGP monitors watch route hijacks in real time.", "bgp-monitor.png", 1.0, 1.12, pan_x=0.03),
    Beat(
        "Campaign intelligence clusters attacks across your deception mesh.",
        "landing-terminal.png",
        1.08,
        1.16,
        pan_y=-0.06,
    ),
    Beat("Today we are open-sourcing the toolkit.", "docs.png", 1.0, 1.1),
    Beat("Canary Kit plants and detects canary tokens.", "docs.png", 1.1, 1.18, pan_y=0.03),
    Beat(
        "Honeypot MITRE maps attacker behavior to the ATT and CK framework.",
        "security.png",
        1.0,
        1.1,
    ),
    Beat("DML Spec defines deception markup for your traps.", "docs.png", 1.0, 1.08, pan_y=0.05),
    Beat(
        "RavenScan audits your repositories before attackers do.",
        "architecture.png",
        1.1,
        1.2,
        pan_y=0.04,
    ),
    Beat(
        "Two repositories: WraithWall toolkit and WraithWall platform.",
        "oss-diagram.png",
        1.0,
        1.1,
    ),
    Beat("MIT licensed, version zero point one zero.", "launch.png", 1.0, 1.06),
    Beat("Star us on GitHub. Visit wraithwall dot online.", "landing-hero.png", 1.06, 1.14),
]

TIMELINE: list[tuple[float, float, Beat]] = []


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * max(0.0, min(1.0, t))


def ease(t: float) -> float:
    return t * t * (3 - 2 * t)


def load_font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    if mono:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        ]
    elif bold:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        ]
    else:
        paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ]
    for path in paths:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def capture_real_screenshots() -> None:
    """Capture live wraithwall.online pages (run when refreshing assets)."""
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
                page.wait_for_timeout(900)
            page.screenshot(path=str(SCREEN_DIR / f"{name}.png"), full_page=False)
            print("captured", name)
        browser.close()


def ken_burns(img: Image.Image, zoom: float, pan_x: float, pan_y: float) -> Image.Image:
    """Crop+zoom into image to fill frame with subtle pan."""
    iw, ih = img.size
    crop_w = int(W / zoom)
    crop_h = int(H / zoom)
    cx = iw / 2 + pan_x * iw
    cy = ih / 2 + pan_y * ih
    left = int(max(0, min(iw - crop_w, cx - crop_w / 2)))
    top = int(max(0, min(ih - crop_h, cy - crop_h / 2)))
    cropped = img.crop((left, top, left + crop_w, top + crop_h))
    return cropped.resize((W, H), Image.Resampling.LANCZOS)


def load_screens() -> dict[str, Image.Image]:
    screens = {}
    for beat in BEATS:
        path = SCREEN_DIR / beat.image
        if not path.exists():
            raise FileNotFoundError(f"Missing screenshot {path} — run capture_real_screenshots()")
        if beat.image not in screens:
            screens[beat.image] = Image.open(path).convert("RGB")
    return screens


def probe_duration(path: Path) -> float:
    return float(
        subprocess.check_output(
            [
                "ffprobe", "-v", "error", "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1", str(path),
            ],
            text=True,
        ).strip()
    )


def synth_beats_edge_tts() -> None:
    """Synthesize each beat with Microsoft Edge neural TTS (African English male)."""
    import asyncio
    import time

    import edge_tts

    async def _synth_one(text: str, mp3: Path, retries: int = 4) -> None:
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                comm = edge_tts.Communicate(text, TTS_VOICE)
                await comm.save(str(mp3))
                return
            except Exception as exc:
                last_err = exc
                await asyncio.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"TTS failed for {mp3.name}") from last_err

    async def _run() -> None:
        for i, beat in enumerate(BEATS):
            mp3 = AUDIO_DIR / f"beat_{i:02d}.mp3"
            if mp3.exists() and mp3.stat().st_size > 1000:
                continue
            await _synth_one(beat.text, mp3)
            time.sleep(0.4)

    asyncio.run(_run())


def build_narration_timeline() -> Path:
    """Per-beat TTS so visuals stay locked to what's being spoken."""
    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    TIMELINE.clear()
    parts: list[Path] = []
    t = 0.0
    gap = 0.18

    print(f"voice: {TTS_VOICE}")
    synth_beats_edge_tts()

    for i, beat in enumerate(BEATS):
        mp3 = AUDIO_DIR / f"beat_{i:02d}.mp3"
        wav = AUDIO_DIR / f"beat_{i:02d}.wav"
        subprocess.run(
            ["ffmpeg", "-y", "-i", str(mp3), "-ar", "44100", "-ac", "2", str(wav)],
            check=True,
            capture_output=True,
        )
        dur = probe_duration(wav)
        TIMELINE.append((t, t + dur, beat))
        t += dur + gap
        parts.append(wav)
        print(f"beat {i:02d} {dur:.1f}s — {beat.text[:50]}…")

    concat_list = AUDIO_DIR / "beats.txt"
    concat_list.write_text("".join(f"file '{p}'\n" for p in parts))
    narration = AUDIO_DIR / "narration.wav"
    subprocess.run(
        [
            "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat_list),
            "-ar", "44100", "-ac", "2", str(narration),
        ],
        check=True,
        capture_output=True,
    )
    return narration


def write_voiceover_guide() -> Path:
    """Timing sheet for replacing AI voice with your own recording."""
    guide = DOCS_DIR / "voiceover-guide.txt"
    script = DOCS_DIR / "voiceover-script.txt"
    lines = [
        "WraithWall OSS — voiceover edit guide",
        f"AI voice used: {TTS_VOICE} (swap with your own recording)",
        "",
        "OPTION A — CapCut (easiest)",
        "1. Download wraithwall-oss-launch-silent.mp4 (no voice, ambient only)",
        "2. Import into CapCut → mute if needed → add your voice track",
        "3. Use the timestamps below to align each line with the on-screen page",
        "4. Export 1280×720 MP4",
        "",
        "OPTION B — Record line-by-line (best sync)",
        "1. Read each numbered line below into your phone mic (quiet room)",
        "2. Leave ~0.2s pause between lines",
        "3. In CapCut/DaVinci: place each clip at the START time shown",
        "",
        "OPTION C — Full freestyle",
        "1. Play the silent video and record one continuous take while watching",
        "2. Re-sync in editor by sliding the audio clip",
        "",
        "TIMELINE (start → end | screenshot shown | say this):",
        "─" * 72,
    ]
    script_lines = []
    for i, (start, end, beat) in enumerate(TIMELINE):
        mm_s, ss_s = divmod(int(start), 60)
        mm_e, ss_e = divmod(int(end), 60)
        lines.append(
            f"{i+1:02d}. {mm_s:02d}:{ss_s:02d} → {mm_e:02d}:{ss_e:02d}  | {beat.image:22s} | {beat.text}"
        )
        script_lines.append(f"{i+1:02d}. {beat.text}")

    lines.extend([
        "─" * 72,
        "",
        "Assets:",
        "  real-screens/          — PNG screenshots per scene",
        "  voiceover-beats/       — individual AI clips (reference pacing)",
        "  wraithwall-oss-launch-silent.mp4 — dub over this",
        "",
        "Swap voice in code: TTS_VOICE in render_oss_video.py",
        "  en-NG-AbeoNeural     Nigerian English male",
        "  en-KE-ChilembaNeural Kenyan English male",
        "  en-ZA-LukeNeural     South African English male",
    ])
    guide.write_text("\n".join(lines) + "\n")
    script.write_text("\n".join(script_lines) + "\n")
    print("wrote", guide)
    return guide


def export_dub_assets(video_noaudio: Path, ambient: Path) -> None:
    """Publish helper files for laptop editing with your own voice."""
    beats_out = STATIC_DIR / "voiceover-beats"
    beats_out.mkdir(parents=True, exist_ok=True)
    for i in range(len(BEATS)):
        src = AUDIO_DIR / f"beat_{i:02d}.mp3"
        if src.exists():
            (beats_out / f"{i+1:02d}.mp3").write_bytes(src.read_bytes())

    for name in ("voiceover-guide.txt", "voiceover-script.txt"):
        src = DOCS_DIR / name
        if src.exists():
            (STATIC_DIR / name).write_text(src.read_text())

    silent = STATIC_DIR / "wraithwall-oss-launch-silent.mp4"
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-i", str(video_noaudio),
            "-i", str(ambient),
            "-filter_complex", "[1]volume=0.35[amb]",
            "-map", "0:v:0", "-map", "[amb]",
            "-c:v", "copy", "-c:a", "aac", "-b:a", "160k",
            "-shortest", "-movflags", "+faststart",
            str(silent),
        ],
        check=True,
        capture_output=True,
    )
    (DOCS_DIR / "wraithwall-oss-launch-silent.mp4").write_bytes(silent.read_bytes())
    print("wrote", silent)


def beat_at_time(t: float) -> tuple[Beat, float, Beat | None, float]:
    """Return current beat, local progress 0-1, optional next beat, crossfade alpha."""
    for i, (start, end, beat) in enumerate(TIMELINE):
        if start <= t < end:
            local = (t - start) / max(end - start, 0.001)
            nxt = TIMELINE[i + 1][2] if i + 1 < len(TIMELINE) else None
            fade = 0.35
            if nxt and t > end - fade:
                alpha = (t - (end - fade)) / fade
                return beat, local, nxt, ease(alpha)
            return beat, local, None, 0.0
    if TIMELINE:
        return TIMELINE[-1][2], 1.0, None, 0.0
    raise RuntimeError("empty timeline")


def draw_caption(img: Image.Image, text: str, alpha: float) -> Image.Image:
    if alpha <= 0 or not text:
        return img
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    font = load_font(16)
    mono = load_font(11, mono=True)

    # Word-wrap caption
    words = text.split()
    lines: list[str] = []
    line = ""
    max_w = W - 120
    for word in words:
        test = f"{line} {word}".strip()
        if draw.textlength(test, font=font) > max_w and line:
            lines.append(line)
            line = word
        else:
            line = test
    if line:
        lines.append(line)

    block_h = 28 + len(lines) * 22
    y0 = H - block_h - 28
    draw.rounded_rectangle([40, y0, W - 40, y0 + block_h], radius=8, fill=CAPTION_BG)
    draw.rectangle([40, y0, 44, y0 + block_h], fill=(*SIGNAL, int(255 * alpha)))
    draw.text((56, y0 + 8), "VOICEOVER", font=mono, fill=(200, 200, 195, int(180 * alpha)))
    for i, ln in enumerate(lines):
        draw.text((56, y0 + 26 + i * 22), ln, font=font, fill=(245, 245, 242, int(255 * alpha)))

    base = img.convert("RGBA")
    return Image.alpha_composite(base, overlay).convert("RGB")


def draw_badge(img: Image.Image, label: str, alpha: float) -> Image.Image:
    if alpha <= 0:
        return img
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    mono = load_font(11, mono=True)
    draw.rounded_rectangle([48, 48, 250, 78], radius=4, fill=(*SIGNAL, int(220 * alpha)))
    draw.text((60, 54), label.upper(), font=mono, fill=(255, 255, 255, int(255 * alpha)))
    base = img.convert("RGBA")
    return Image.alpha_composite(base, overlay).convert("RGB")


def render_beat_frame(screens: dict[str, Image.Image], beat: Beat, local: float) -> Image.Image:
    img = screens[beat.image]
    zoom = lerp(beat.zoom_start, beat.zoom_end, ease(local))
    pan_x = lerp(0, beat.pan_x, ease(local))
    pan_y = lerp(0, beat.pan_y, ease(local))
    return ken_burns(img, zoom, pan_x, pan_y)


def render_frame(i: int, screens: dict[str, Image.Image]) -> Image.Image:
    t = i / FPS
    beat, local, nxt, xfade = beat_at_time(t)

    frame = render_beat_frame(screens, beat, local)
    if nxt and xfade > 0:
        nxt_frame = render_beat_frame(screens, nxt, 0.0)
        frame = Image.blend(frame, nxt_frame, xfade)

    # Intro / outro fades
    if t < 0.8:
        fade = 1 - ease(t / 0.8)
        black = Image.new("RGB", (W, H), (0, 0, 0))
        frame = Image.blend(black, frame, 1 - fade)
    if t > DURATION - 1.2:
        fade = ease((t - (DURATION - 1.2)) / 1.2)
        paper = Image.new("RGB", (W, H), (250, 250, 247))
        frame = Image.blend(frame, paper, fade)

    frame = draw_badge(frame, "live · wraithwall.online", 0.85)
    frame = draw_caption(frame, beat.text if xfade < 0.5 else (nxt.text if nxt else beat.text), 0.92)
    return frame


def build_ambient(duration: float) -> Path:
    AUDIO_DIR.mkdir(parents=True, exist_ok=True)
    bed = AUDIO_DIR / "ambient.wav"
    filt = (
        f"[0]volume=0.08,lowpass=f=180[a];"
        f"[1]volume=0.05,lowpass=f=320[b];"
        f"[2]volume=0.025,lowpass=f=800[c];"
        f"[a][b][c]amix=inputs=3:duration=first,"
        f"afade=t=in:st=0:d=2,afade=t=out:st={duration - 3}:d=3"
    )
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-f", "lavfi", "-i", f"sine=frequency=55:duration={duration}",
            "-f", "lavfi", "-i", f"sine=frequency=110:duration={duration}",
            "-f", "lavfi", "-i", f"anoisesrc=color=pink:duration={duration}:amplitude=0.4",
            "-filter_complex", filt,
            "-ar", "44100", "-ac", "2",
            str(bed),
        ],
        check=True,
        capture_output=True,
    )
    return bed


def mix_audio(narration: Path, ambient: Path, duration: float) -> Path:
    mixed = AUDIO_DIR / "mixed.wav"
    filt = (
        "[0]volume=0.32[amb];"
        "[1]volume=1.2[vox];"
        "[amb][vox]amix=inputs=2:duration=longest:weights=0.45 1.0,"
        f"apad=pad_dur={duration},atrim=0:{duration},"
        f"afade=t=out:st={max(0, duration - 2.5)}:d=2.5"
    )
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-i", str(ambient),
            "-i", str(narration),
            "-filter_complex", filt,
            "-ar", "44100", "-ac", "2",
            str(mixed),
        ],
        check=True,
        capture_output=True,
    )
    return mixed


def mux_video(audio: Path) -> None:
    out_with_audio = Path("/tmp/wraithwall-oss-launch-audio.mp4")
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-i", str(OUT_MP4),
            "-i", str(audio),
            "-c:v", "copy",
            "-c:a", "aac", "-b:a", "192k",
            "-shortest",
            "-movflags", "+faststart",
            str(out_with_audio),
        ],
        check=True,
    )
    OUT_MP4.write_bytes(out_with_audio.read_bytes())


def main():
    global FRAMES, DURATION

    screens = load_screens()
    print(f"loaded {len(screens)} real screenshots from {SCREEN_DIR}")

    print("=== building per-beat narration ===")
    narration = build_narration_timeline()
    narr_dur = probe_duration(narration)
    DURATION = narr_dur + 1.5
    FRAMES = int(FPS * DURATION)
    print(f"timeline {len(TIMELINE)} beats, {narr_dur:.1f}s audio, {DURATION:.1f}s video")

    print("=== rendering frames (real UI) ===")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for old in OUT_DIR.glob("frame_*.png"):
        old.unlink()
    for i in range(FRAMES):
        render_frame(i, screens).save(OUT_DIR / f"frame_{i:04d}.png")
        if i % 48 == 0:
            print(f"frame {i}/{FRAMES}")

    print("=== encoding video ===")
    video_raw = Path("/tmp/wraithwall-oss-launch-video.mp4")
    subprocess.run(
        [
            "ffmpeg", "-y", "-framerate", str(FPS),
            "-i", str(OUT_DIR / "frame_%04d.png"),
            "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-crf", "18", "-movflags", "+faststart",
            str(video_raw),
        ],
        check=True,
    )
    OUT_MP4.write_bytes(video_raw.read_bytes())

    write_voiceover_guide()

    print("=== building ambient + mix ===")
    ambient = build_ambient(DURATION)
    mixed = mix_audio(narration, ambient, DURATION)

    print("=== muxing audio ===")
    mux_video(mixed)
    export_dub_assets(video_raw, ambient)

    for dest in (
        DOCS_DIR / "wraithwall-oss-launch.mp4",
        STATIC_DIR / "wraithwall-oss-launch.mp4",
    ):
        dest.write_bytes(OUT_MP4.read_bytes())
        print("wrote", dest, f"({dest.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "capture":
        capture_real_screenshots()
    else:
        main()