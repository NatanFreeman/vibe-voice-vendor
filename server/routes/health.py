import httpx
from fastapi import APIRouter, Request

from server.config import Settings

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> dict[str, str]:
    http_client: httpx.AsyncClient = request.app.state.http_client
    settings: Settings = request.app.state.settings

    if settings.asr_backend == "groq":
        return {"status": "ok", "asr_backend": "groq"}

    try:
        resp = await http_client.get(f"{settings.vllm_base_url}/health", timeout=5.0)
        vllm_status = "ok" if resp.status_code == 200 else "degraded"
    except Exception:
        vllm_status = "unreachable"

    return {"status": "ok", "vllm": vllm_status}
