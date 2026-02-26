import os
from dataclasses import dataclass


def _parse_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


_default_postgres_dsn = os.getenv("POSTGRES_DSN", "postgresql+asyncpg://ekyc:ekyc@localhost:5432/ekyc")
_default_app_db_dsn = os.getenv("APP_DB_DSN", "sqlite+aiosqlite:///./ekyc_local.db")


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    cors_origins_raw: str = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    postgres_dsn: str = _default_postgres_dsn
    app_db_dsn: str = _default_app_db_dsn
    mongodb_uri: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongodb_db: str = os.getenv("MONGODB_DB", "ekyc")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    jwt_secret: str = os.getenv("JWT_SECRET", "change_me_in_production")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
    auto_create_schema: bool = _parse_bool(os.getenv("AUTO_CREATE_SCHEMA"), True)
    upload_root: str = os.getenv("UPLOAD_ROOT", "storage/uploads")
    report_root: str = os.getenv("REPORT_ROOT", "storage/reports")
    max_upload_size_mb: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
    max_video_size_mb: int = int(os.getenv("MAX_VIDEO_SIZE_MB", "30"))
    face_landmark_model_path: str = os.getenv(
        "FACE_LANDMARK_MODEL_PATH",
        "storage/models/shape_predictor_81_face_landmarks.dat",
    )
    face_landmark_model_url: str = os.getenv(
        "FACE_LANDMARK_MODEL_URL",
        "https://raw.githubusercontent.com/codeniko/shape_predictor_81_face_landmarks/master/shape_predictor_81_face_landmarks.dat",
    )
    face_crop_padding_ratio: float = float(os.getenv("FACE_CROP_PADDING_RATIO", "0.25"))
    face_similarity_space_url: str = os.getenv(
        "FACE_SIMILARITY_SPACE_URL",
        "https://cvdetectors-humandetector.hf.space",
    )
    face_similarity_api_name: str = os.getenv("FACE_SIMILARITY_API_NAME", "/predict")
    face_match_pass_threshold: float = float(os.getenv("FACE_MATCH_PASS_THRESHOLD", "70"))
    liveness_space_url: str = os.getenv(
        "LIVENESS_SPACE_URL",
        "https://cvdetectors-liveness-detector.hf.space",
    )
    liveness_api_name: str = os.getenv("LIVENESS_API_NAME", "/predict")
    liveness_live_threshold: float = float(os.getenv("LIVENESS_LIVE_THRESHOLD", "65"))
    external_api_timeout_seconds: float = float(os.getenv("EXTERNAL_API_TIMEOUT_SECONDS", "90"))
    deepfake_space_url: str = os.getenv("DEEPFAKE_SPACE_URL", "Dharshaneshwaran/deepfake")
    deepfake_api_name: str = os.getenv("DEEPFAKE_API_NAME", "/predict_3")
    deepfake_hf_token: str | None = os.getenv("DEEPFAKE_HF_TOKEN")
    deepfake_timeout_seconds: float = float(os.getenv("DEEPFAKE_TIMEOUT_SECONDS", "90"))
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]


settings = Settings()
