import os
from dataclasses import dataclass


def _parse_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    cors_origins_raw: str = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    postgres_dsn: str = os.getenv(
        "POSTGRES_DSN", "postgresql+asyncpg://ekyc:ekyc@localhost:5432/ekyc"
    )
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_db: str = os.getenv("MONGODB_DB", "ekyc")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    jwt_secret: str = os.getenv("JWT_SECRET", "change_me_in_production")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
    auto_create_schema: bool = _parse_bool(os.getenv("AUTO_CREATE_SCHEMA"), True)
    upload_root: str = os.getenv("UPLOAD_ROOT", "storage/uploads")
    max_upload_size_mb: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    max_video_size_mb: int = int(os.getenv("MAX_VIDEO_SIZE_MB", "30"))

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]


settings = Settings()
