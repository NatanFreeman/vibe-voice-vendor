import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from server.audio import detect_mime_type, encode_audio_base64, probe_duration
from server.auth import verify_token
from server.models import ErrorEvent, QueuePositionEvent, TranscriptionChunkEvent
from server.queue import TranscriptionJob, TranscriptionQueue

router = APIRouter()


@router.post("/v1/transcribe")
async def transcribe(
    request: Request,
    audio: UploadFile,
    token_fingerprint: Annotated[str, Depends(verify_token)],
    hotwords: str | None = None,
) -> StreamingResponse:
    queue: TranscriptionQueue = request.app.state.queue
    max_audio_bytes: int = request.app.state.settings.max_audio_bytes

    audio_bytes = await audio.read()
    if len(audio_bytes) > max_audio_bytes:
        raise HTTPException(status_code=413, detail="Audio file too large")

    if len(audio_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty audio file")

    audio_b64 = encode_audio_base64(audio_bytes)
    if audio.filename is None:
        raise HTTPException(status_code=400, detail="Audio file must include a filename")
    try:
        mime_type = detect_mime_type(audio.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    try:
        duration = await probe_duration(audio_bytes)
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=f"Cannot read audio: {exc}") from None

    job = TranscriptionJob(
        token_fingerprint=token_fingerprint,
        audio_base64=audio_b64,
        audio_mime=mime_type,
        hotwords=hotwords,
        audio_duration_seconds=duration,
    )

    try:
        queue.enqueue(job)
    except asyncio.QueueFull:
        raise HTTPException(status_code=503, detail="Queue is full") from None

    async def event_stream() -> AsyncIterator[str]:
        # Send initial queue position
        position, eta = queue.get_position_and_eta(job.job_id)
        if position is not None:
            assert eta is not None, f"ETA must not be None when position={position} is not None"
            event = QueuePositionEvent(
                job_id=job.job_id,
                position=position,
                estimated_wait_seconds=eta,
            )
            yield f"event: queue\ndata: {event.model_dump_json()}\n\n"

        # Stream transcription chunks
        while True:
            chunk = await job.chunk_queue.get()
            if chunk is None:
                break

            chunk_event = TranscriptionChunkEvent(text=chunk)
            yield f"data: {chunk_event.model_dump_json()}\n\n"

        # Send final event
        if job.error_message is not None:
            error_event = ErrorEvent(error=job.error_message)
            yield f"event: error\ndata: {error_event.model_dump_json()}\n\n"
        else:
            yield f"event: done\ndata: {json.dumps({'job_id': job.job_id})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
