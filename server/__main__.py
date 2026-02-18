import argparse

import uvicorn

from server.app import create_app
from server.config import Settings


def _parse_bool(value: str) -> bool:
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    raise argparse.ArgumentTypeError(f"Expected true/false, got: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vvv-server",
        description="VibeVoice ASR Server",
    )
    parser.add_argument("--vllm-base-url", required=True, help="vLLM server base URL")
    parser.add_argument("--host", required=True, help="Server bind address")
    parser.add_argument("--port", type=int, required=True, help="Server bind port")
    parser.add_argument(
        "--max-audio-bytes", type=int, required=True, help="Maximum audio upload size in bytes"
    )
    parser.add_argument(
        "--max-queue-size", type=int, required=True, help="Maximum number of queued jobs"
    )
    parser.add_argument(
        "--jwt-public-key-file", required=True, help="Path to ES256 public key PEM file"
    )
    parser.add_argument(
        "--revoked-tokens-file", required=True, help="Path to file listing revoked JTI values"
    )
    parser.add_argument(
        "--require-https",
        type=_parse_bool,
        required=True,
        help="Reject non-HTTPS requests (true/false)",
    )
    parser.add_argument("--vllm-model-name", required=True, help="Model name for vLLM")
    parser.add_argument(
        "--vllm-max-tokens", type=int, required=True, help="Maximum output tokens"
    )
    parser.add_argument(
        "--vllm-temperature", type=float, required=True, help="Generation temperature"
    )
    parser.add_argument(
        "--vllm-top-p", type=float, required=True, help="Top-P sampling parameter"
    )

    args = parser.parse_args()

    settings = Settings(
        vllm_base_url=args.vllm_base_url,
        server_host=args.host,
        server_port=args.port,
        max_audio_bytes=args.max_audio_bytes,
        max_queue_size=args.max_queue_size,
        jwt_public_key_file=args.jwt_public_key_file,
        revoked_tokens_file=args.revoked_tokens_file,
        require_https=args.require_https,
        vllm_model_name=args.vllm_model_name,
        vllm_max_tokens=args.vllm_max_tokens,
        vllm_temperature=args.vllm_temperature,
        vllm_top_p=args.vllm_top_p,
    )

    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.server_host,
        port=settings.server_port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
