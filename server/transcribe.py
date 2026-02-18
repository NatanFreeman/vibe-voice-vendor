import httpx

from server.config import Settings
from server.models import JobStatus
from server.queue import TranscriptionJob
from server.vllm_client import stream_transcription


async def process_transcription_job(
    job: TranscriptionJob,
    http_client: httpx.AsyncClient,
    config: Settings,
) -> None:
    """Worker function that processes a single transcription job."""
    first_chunk = True
    async for chunk in stream_transcription(
        http_client=http_client,
        vllm_base_url=config.vllm_base_url,
        model_name=config.vllm_model_name,
        audio_base64=job.audio_base64,
        audio_mime=job.audio_mime,
        audio_duration=job.audio_duration_seconds,
        hotwords=job.hotwords,
        temperature=config.vllm_temperature,
        top_p=config.vllm_top_p,
    ):
        if first_chunk:
            job.status = JobStatus.STREAMING
            first_chunk = False
        await job.chunk_queue.put(chunk)

    # Signal end of stream
    await job.chunk_queue.put(None)
