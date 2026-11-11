#!/usr/bin/env python3
"""Download a complete ordinary public source. No authentication or access bypass."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request

case_file, destination, report_file = map(pathlib.Path, sys.argv[1:4])
case = json.loads(case_file.read_text(encoding="utf-8"))
destination.parent.mkdir(parents=True, exist_ok=True)
MAX_BYTES = 2_000_000_000

def fetch(url, referer=None):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Source URL must use HTTPS")
    headers = {"User-Agent": "Mozilla/5.0"}
    if referer:
        headers["Referer"] = referer
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45)

expected = float(case.get("duration_sec") or 0)
platform = case["platform"]
media_url = case.get("download_url") or case.get("media_url")
referer = case.get("referer")
if platform == "rutube":
    video_id = case["video_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", video_id):
        raise ValueError("Invalid RUTUBE video ID")
    with fetch("https://rutube.ru/api/play/options/" + video_id + "/") as response:
        options = json.load(response)
    if any(options.get(flag) is True for flag in ("is_hidden", "is_private", "is_adult", "is_paid")):
        raise RuntimeError("Source is restricted; choose an unrestricted public lecture")
    expected = float(options["duration"]) / 1000
    master = options["video_balancer"]["m3u8"]
    referer = "https://rutube.ru/"
    with fetch(master, referer) as response:
        playlist = response.read().decode("utf-8")
    if not playlist.startswith("#EXTM3U"):
        raise RuntimeError("Public player did not return HLS")
    lines = playlist.splitlines()
    variants = []
    for index, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF:"):
            match = re.search(r"RESOLUTION=(\d+)x(\d+)", line)
            if match:
                variants.append((int(match.group(2)), urllib.parse.urljoin(master, lines[index + 1])))
    eligible = [item for item in variants if item[0] <= int(case.get("max_height", 720))]
    if not eligible:
        raise RuntimeError("No suitable unrestricted public HLS variant")
    _, media_url = max(eligible)
elif platform not in ("direct", "hls"):
    raise ValueError("Supported platforms: rutube, direct, hls")

if platform == "direct":
    with fetch(media_url, referer) as response, destination.open("wb") as output:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_BYTES:
                raise RuntimeError("Source exceeds the app's 2 GB input limit")
            output.write(chunk)
else:
    if urllib.parse.urlparse(media_url).scheme != "https":
        raise ValueError("HLS URL must use HTTPS")
    command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "warning",
               "-user_agent", "Mozilla/5.0"]
    if referer:
        command += ["-headers", "Referer: " + referer + "\r\n"]
    command += ["-i", media_url, "-c", "copy", "-movflags", "+faststart", "-y", str(destination)]
    # Read the entire normal VOD playlist. No -t, trimming, credentials, or player bypass.
    subprocess.run(command, check=True)

if not destination.exists() or not 0 < destination.stat().st_size <= MAX_BYTES:
    raise RuntimeError("Downloaded media is empty, missing, or exceeds 2 GB")
probe = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(destination)]))
duration = float(probe["format"]["duration"])
kinds = {stream["codec_type"] for stream in probe["streams"]}
if not {"video", "audio"}.issubset(kinds):
    raise RuntimeError("Lecture must contain real video and audio tracks")
if duration > 10800:
    raise RuntimeError("Source exceeds the app's 180-minute limit")
if expected and abs(duration - expected) > max(2, expected * .005):
    raise RuntimeError("Downloaded duration does not match the complete public source")
digest = hashlib.sha256()
with destination.open("rb") as source:
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
record = {
    "id": case["id"], "title": case["title"], "source_url": case["source_url"],
    "platform": platform, "duration_sec": duration, "expected_duration_sec": expected,
    "bytes": destination.stat().st_size, "sha256": digest.hexdigest(),
    "method": "Complete public source, no trimming or authentication",
    "streams": [{key: stream.get(key) for key in ("codec_type", "codec_name", "width", "height", "sample_rate", "channels", "avg_frame_rate")} for stream in probe["streams"]],
}
report_file.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"id": case["id"], "duration_sec": duration, "bytes": record["bytes"]}), flush=True)
