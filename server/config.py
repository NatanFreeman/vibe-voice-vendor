from typing import Literal

from pydantic import BaseModel


class Settings(BaseModel):
    asr_backend: Literal["vibevoice", "groq"]
    server_host: str
    server_port: int
    max_audio_bytes: int
    max_queue_size: int
    jwt_public_key_file: str
    revoked_tokens_file: str
    require_https: bool
    # vLLM / VibeVoice settings (used when asr_backend == "vibevoice")
    vllm_base_url: str
    vllm_model_name: str
    vllm_temperature: float
    vllm_top_p: float
    # Groq Whisper settings (used when asr_backend == "groq")
    groq_api_key: str
    groq_model_name: str
