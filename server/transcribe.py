import httpx

from server.config import Settings
from server.groq_client import transcribe_audio
from server.models import JobStatus
from server.queue import TranscriptionJob
from server.vllm_client import stream_transcription


async def process_vibevoice_job(
    job: TranscriptionJob,
    http_client: httpx.AsyncClient,
    config: Settings,
) -> None:
    """Worker function that processes a job via local vLLM VibeVoice."""
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


async def process_groq_job(
    job: TranscriptionJob,
    http_client: httpx.AsyncClient,
    config: Settings,
) -> None:
    """Worker function that processes a job via Groq Whisper API."""
    job.status = JobStatus.STREAMING
    text = await transcribe_audio(
        http_client=http_client,
        api_key=config.groq_api_key,
        model_name=config.groq_model_name,
        audio_base64=job.audio_base64,
        audio_mime=job.audio_mime,
        hotwords=job.hotwords,
    )
    if text:
        await job.chunk_queue.put(text)

    # Signal end of stream
    await job.chunk_queue.put(None)
