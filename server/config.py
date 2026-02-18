from pydantic import BaseModel


class Settings(BaseModel):
    vllm_base_url: str
    server_host: str
    server_port: int
    max_audio_bytes: int
    max_queue_size: int
    jwt_public_key_file: str
    revoked_tokens_file: str
    require_https: bool
    vllm_model_name: str
    vllm_temperature: float
    vllm_top_p: float
