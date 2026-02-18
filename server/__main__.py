import uvicorn

from server.app import create_app
from server.config import Settings


def main() -> None:
    settings = Settings()
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
