from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 1280
HEIGHT = 720
FPS = 24
BG = (15, 23, 42)
WHITE = (226, 232, 240)
MUTED = (148, 163, 184)
GREEN = (74, 222, 128)
AMBER = (251, 191, 36)
RED = (248, 113, 113)
BLUE = (96, 165, 250)


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )
    selected = candidates[0] if bold else candidates[1]
    return ImageFont.truetype(selected, size)


def draw_wrapped(draw: ImageDraw.ImageDraw, text: str, x: int, y: int, width: int, fnt: ImageFont.FreeTypeFont, fill: tuple[int, int, int], line_gap: int = 8) -> int:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if draw.textlength(candidate, font=fnt) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    line_height = fnt.size + line_gap
    for index, line in enumerate(lines):
        draw.text((x, y + index * line_height), line, font=fnt, fill=fill)
    return y + len(lines) * line_height


def frame_base(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, WIDTH, 92), fill=(30, 41, 59))
    draw.text((48, 24), title, font=font(32, True), fill=WHITE)
    draw.text((48, 62), subtitle, font=font(18), fill=MUTED)
    draw.text((1080, 28), "AEGISHUB", font=font(22, True), fill=BLUE)
    draw.text((1080, 57), "LOCAL PoC", font=font(16, True), fill=AMBER)
    return image, draw


def status_color(value: str) -> tuple[int, int, int]:
    if value == "expected":
        return GREEN
    if value == "anomalous":
        return RED
    return AMBER


def make_frame(path: Path, title: str, subtitle: str, body: list[tuple[str, tuple[int, int, int]]], footer: str) -> None:
    image, draw = frame_base(title, subtitle)
    y = 136
    for text, color in body:
        y = draw_wrapped(draw, text, 64, y, WIDTH - 128, font(26), color, line_gap=12) + 18
    draw.line((64, HEIGHT - 86, WIDTH - 64, HEIGHT - 86), fill=(51, 65, 85), width=2)
    draw.text((64, HEIGHT - 62), footer, font=font(17), fill=MUTED)
    image.save(path)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: make_phase2_poc_video.py <summary.json> <output.mp4>", file=sys.stderr)
        return 2
    summary_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    results = {item["mode"]: item for item in summary["results"]}
    safe = results["safe"]
    bypass = results["bypass"]

    frames = output_path.parent / ".phase2-poc-video-frames"
    if frames.exists():
        shutil.rmtree(frames)
    frames.mkdir(parents=True)
    frame_number = 0

    def add(title: str, subtitle: str, body: list[tuple[str, tuple[int, int, int]]], footer: str, seconds: float) -> None:
        nonlocal frame_number
        count = max(1, int(seconds * FPS))
        for _ in range(count):
            frame_number += 1
            make_frame(frames / f"frame_{frame_number:05d}.png", title, subtitle, body, footer)

    add(
        "AegisHub Bounty Mode — Phase 2",
        "Screen-demo generated from a sanitized loopback summary",
        [
            ("Scope: 127.0.0.1 fake GitHub server only", BLUE),
            ("No GitHub request • no real token • no third-party data", GREEN),
            ("Question: do fixed REST and GraphQL interfaces enforce the same private-marker boundary?", WHITE),
        ],
        "Synthetic lab fixture • no severity claim",
        4.0,
    )
    add(
        "1 — Safe boundary",
        "Owner baseline + researcher probes + owner repeat",
        [
            (f"result = {safe['result']}", status_color(safe["result"])),
            (f"requests = {safe['requestCount']}    mutations = {safe['mutationCount']}", WHITE),
            (f"protected untrusted observations = {safe['protectedUntrustedObservations']}", GREEN),
            ("cosmetic differences are not promoted", GREEN),
        ],
        "Expected safe outcome",
        5.0,
    )
    add(
        "2 — Synthetic bypass toggle",
        "Local fake server returns the protected marker to the untrusted actor",
        [
            ("This is a test fixture, not a GitHub finding", AMBER),
            (f"protected untrusted observations = {bypass['protectedUntrustedObservations']}", RED),
            (f"candidate repetitions = {bypass.get('candidateReproductionCount', '—')}", RED),
            ("impact: synthetic lab-owned confidentiality only", WHITE),
        ],
        "candidate-stop threshold reached",
        5.0,
    )
    add(
        "3 — Candidate-stop",
        "The runner stops before the fixed GraphQL follow-up",
        [
            (f"result = {bypass['result']}", status_color(bypass["result"])),
            (f"reason = {bypass.get('reason', '—')}", RED),
            (f"requests = {bypass['requestCount']}    mutations = {bypass['mutationCount']}", WHITE),
            (f"stopped before follow-up = {bypass['stoppedBeforeFollowUp']}", GREEN),
            ("No exploit expansion • no severity assignment • no submission", GREEN),
        ],
        "Candidate means human review required — not confirmed vulnerability",
        5.0,
    )
    add(
        "4 — Sanitized evidence",
        "Only normalized fields are exported",
        [
            ("allowlist: actor • status • operation ID • protectedData • hashes", BLUE),
            ("redacted: tokens • cookies • nonce • raw bodies • PII", GREEN),
            ("next step: human review before any separate live approval", WHITE),
        ],
        "AegisHub local PoC complete",
        4.0,
    )

    subprocess.run(
        [
            "ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
            "-i", str(frames / "frame_%05d.png"), "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-movflags", "+faststart", str(output_path),
        ],
        check=True,
    )
    shutil.rmtree(frames)
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
