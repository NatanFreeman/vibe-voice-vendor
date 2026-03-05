import asyncio
import base64
import json
import os
import tempfile
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


def detect_mime_type(filename: str) -> str:
    """Detect audio MIME type from filename extension.

    Raises ValueError if the extension is not recognized.
    The caller must provide a filename with a supported audio extension.
    """
    suffix = PurePosixPath(filename).suffix.lower()
    if suffix not in _MIME_MAP:
        raise ValueError(
            f"Unrecognized audio extension '{suffix}' in filename '{filename}'. "
            f"Supported extensions: {', '.join(sorted(_MIME_MAP.keys()))}"
        )
    return _MIME_MAP[suffix]


async def compress_to_opus(raw_bytes: bytes) -> bytes:
    """Compress audio to OGG/Opus via ffmpeg. Keeps file size small for cloud APIs."""
    with tempfile.NamedTemporaryFile(suffix=".audio") as src:
        src.write(raw_bytes)
        src.flush()
        with tempfile.NamedTemporaryFile(suffix=".ogg", delete=False) as dst:
            dst_path = dst.name

        try:
            process = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-y",
                "-i", src.name,
                "-vn",
                "-ac", "1",
                "-ar", "16000",
                "-c:a", "libopus",
                "-b:a", "64k",
                dst_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_data = await process.communicate()
            if process.returncode != 0:
                err = stderr_data.decode("utf-8", errors="replace")
                raise RuntimeError(f"ffmpeg opus compression failed: {err}")

            with open(dst_path, "rb") as f:
                return f.read()
        finally:
            os.unlink(dst_path)


async def probe_duration(raw_bytes: bytes) -> float:
    """Get audio duration in seconds via ffprobe without transcoding.

    Uses a temp file instead of stdin pipe because ffprobe cannot determine
    duration for some formats (e.g. WAV) when reading from a pipe.
    """
    with tempfile.NamedTemporaryFile(suffix=".audio") as tmp:
        tmp.write(raw_bytes)
        tmp.flush()

        process = await asyncio.create_subprocess_exec(
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            tmp.name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

    if process.returncode != 0:
        error_msg = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"ffprobe failed: {error_msg}")

    info = json.loads(stdout)
    if "format" not in info:
        raise RuntimeError("ffprobe output missing 'format' key")
    if "duration" not in info["format"]:
        raise RuntimeError("ffprobe could not determine audio duration")
    return float(info["format"]["duration"])
