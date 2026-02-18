import asyncio
import base64
import json
from pathlib import PurePosixPath

_MIME_MAP = {
    ".wav": "audio/wav",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".mp4": "audio/mp4",
    ".flac": "audio/flac",
    ".ogg": "audio/ogg",
    ".opus": "audio/ogg",
    ".webm": "audio/webm",
    ".wma": "audio/x-ms-wma",
    ".aac": "audio/aac",
}


def encode_audio_base64(raw_bytes: bytes) -> str:
    """Base64-encode raw audio bytes without any conversion."""
    return base64.b64encode(raw_bytes).decode("ascii")


def guess_mime_type(filename: str | None) -> str:
    """Guess audio MIME type from filename extension."""
    if filename:
        suffix = PurePosixPath(filename).suffix.lower()
        if suffix in _MIME_MAP:
            return _MIME_MAP[suffix]
    return "application/octet-stream"


async def probe_duration(raw_bytes: bytes) -> float:
    """Get audio duration in seconds via ffprobe without transcoding."""
    process = await asyncio.create_subprocess_exec(
        "ffprobe",
        "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        "-i", "pipe:0",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(input=raw_bytes)

    if process.returncode != 0:
        error_msg = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"ffprobe failed: {error_msg}")

    info = json.loads(stdout)
    duration_str = info.get("format", {}).get("duration")
    if duration_str is None:
        raise RuntimeError("ffprobe could not determine audio duration")
    return float(duration_str)
