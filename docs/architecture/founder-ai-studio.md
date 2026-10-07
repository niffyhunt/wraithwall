# WraithWall Founder AI Studio — Architecture v2

**Status:** Architecture + phased implementation
**Date:** 2026-07-18

---

## Identity Training vs Content Generation

The uploaded founder video (`founder_video.mp4`, 508 MB) is **permanent identity training data** — never republished as-is. Extracted assets under `/opt/wraithwall/media/branding/`:

| Asset | Purpose |
|-------|---------|
| `founder_photo.png` | Face reference for avatar generation |
| `founder_voice.wav` | Voice profile for TTS cloning |
| `voice_profile.json` | TTS parameters (pitch, speed, cadence) |
| `founder_video.mp4` | Full reference (facial expressions, head movement, eye tracking) |

Rule: future videos generate entirely new scripts. Original spoken words are NEVER reused.

---

## Pipeline v2: Research → Video

```
1. RESEARCH           Browser-based fact collection from trusted sources
     ↓
2. FACT VERIFICATION  Cross-reference findings, confidence scoring
     ↓
3. ARTICLE            Full technical article (blog + LinkedIn)
     ↓
4. X THREAD           Condensed thread format
     ↓
5. VIDEO SCRIPT       Shot-by-shot with visual descriptions
     ↓
6. SCENE PLANNING     Background selection, camera angles, transitions
     ↓
7. DIAGRAM GEN        Architecture, attack chain, MITRE, timeline visuals
     ↓
8. B-ROLL             Terminal recordings, packet flows, threat maps
     ↓
9. AVATAR             Founder face animation with lip sync
     ↓
10. VOICE SYNTHESIS  TTS from founder voice profile
     ↓
11. RENDER            1080p + 4K with audio mastering
     ↓
12. SOCIAL CUTS       YouTube Shorts, TikTok, Instagram, X, LinkedIn
     ↓
13. THUMBNAILS        Platform-specific optimized thumbnails
     ↓
14. PUBLISH PKG       Captions, hashtags, descriptions, posting times
     ↓
15. TELEGRAM          Automatic notification with output paths + preview
```

---

## Dynamic Background Engine

Background selection based on topic classification:

| Topic Category | Background |
|----------------|-----------|
| Cyber deception / honeypots | Blue SOC with attack map display |
| Threat intelligence / campaigns | Intelligence operations center |
| Cloud security / AWS | Cloud architecture visualization wall |
| Reverse engineering / malware | Binary analysis workstation |
| AI security / LLM threats | Modern AI laboratory with neural visualizations |
| Research papers / CVEs | Minimal clean engineering office |
| BGP / Network attacks | Network operations center with route maps |
| CISA / Government advisories | Dark professional briefing room |

Implementation: topic keyword matching → selects background class → ffmpeg chroma key / overlay with founder face composite.

---

## Visual Intelligence Engine

Auto-generated visuals during video:

| Visual Type | Generation Method |
|-------------|------------------|
| Architecture diagrams | Mermaid.js → PNG (programmatic) |
| Attack chain animations | ffmpeg drawtext + timed overlays |
| Terminal simulations | Pre-recorded SSH sessions from Cowrie |
| Packet flow animations | Particle effects via ffmpeg |
| MITRE ATT&CK graphics | Color-coded technique grid overlay |
| Timeline animations | Animated progress bar with event markers |
| Threat maps | GeoIP coordinates → world map overlay |
| Campaign graphs | NetworkX → graph visualization |
| Comparison tables | ffmpeg drawtext table rendering |
| Network topology | Mermaid flowchart → animated reveal |

---

## Output Manifest

For every topic, the pipeline produces:

```json
{
  "job_id": "...",
  "title": "...",
  "outputs": {
    "full_article":     "article.md",
    "linkedin_article": "article_linkedin.md",
    "x_thread":         "thread.json",
    "short_60s":        "output_tiktok.mp4",
    "explanation_3m":   "output_youtube_shorts.mp4",
    "youtube_8_12m":   "output_1080p.mp4",
    "thumbnail":        "thumb_main.png",
    "captions":         "subtitles.srt",
    "descriptions": {
      "youtube": "...",
      "linkedin": "...",
      "x": "...",
      "tiktok": "...",
      "instagram": "..."
    },
    "hashtags": ["#cybersecurity", "#wraithwall", ...],
    "posting_schedule": {
      "optimal_time_utc": "14:00",
      "platforms": ["youtube", "linkedin", "x"]
    }
  },
  "telegram_announcement": "...",
  "render_stats": {
    "duration_s": 342,
    "resolutions": ["1080p", "4K"],
    "warnings": []
  }
}
```

---

## Telegram Integration

After every render, automatically send:

- Job ID
- Title and topic
- Output directory path
- Render duration
- Thumbnail preview (as photo)
- Available resolutions
- Platform variants generated
- Any warnings or partially failed stages

---

## API Dependencies Status

| Service | Status | Action |
|---------|--------|--------|
| Groq Chat Completions | Working | Script generation |
| Groq Whisper | 403 | Install local openai-whisper |
| Groq TTS | 400 | Configure ElevenLabs or Coqui TTS |
| DeepSeek Chat | Working via existing key | Fallback LLM |
| FFmpeg | Working | Rendering, thumbnails, cuts |

---

## Phased Implementation

### Phase 1 — Foundation (done)
- [x] Audio extraction
- [x] Script generation (LLM)
- [x] Video assembly (ffmpeg)
- [x] Thumbnails + social cuts
- [x] Branding pipeline
- [x] Queue claim system
- [x] Telegram notifications

### Phase 2 — Intelligence (next)
- [ ] Install local whisper for transcription
- [ ] Configure working TTS (ElevenLabs / Coqui)
- [ ] Research pipeline (browser-based fact collection)
- [ ] Article generation (LLM from research)
- [ ] X thread generation
- [ ] Automated diagram generation (Mermaid.js)

### Phase 3 — Production Quality
- [ ] Wav2Lip / SadTalker for photorealistic lip sync
- [ ] Dynamic background compositing
- [ ] B-roll asset library
- [ ] Automated terminal recording (from Cowrie sessions)
- [ ] Visual intelligence engine
- [ ] Publishing package generation

### Phase 4 — Autonomous Studio
- [ ] Continuous topic discovery (from intel collector)
- [ ] Trending cybersecurity topic detection
- [ ] Auto-scheduling of content calendar
- [ ] A/B testing of thumbnails/titles
- [ ] Performance analytics
- [ ] Content repurposing (video → article → thread → short)
