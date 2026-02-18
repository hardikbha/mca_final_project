from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db_session
from app.deps import get_current_user
from app.models.user import User
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: RegisterRequest, db: AsyncSession = Depends(get_db_session)
) -> AuthResponse:
    normalized_email = payload.email.strip().lower()
    normalized_phone = payload.phone.strip()
    existing = await db.scalar(
        select(User).where(or_(User.email == normalized_email, User.phone == normalized_phone))
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone already registered",
        )

    user = User(
        full_name=payload.full_name.strip(),
        email=normalized_email,
        phone=normalized_phone,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(subject=str(user.user_id), role=user.role.value)
    return AuthResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=AuthResponse)
async def login_user(
    payload: LoginRequest, db: AsyncSession = Depends(get_db_session)
) -> AuthResponse:
    identifier = payload.identifier.strip().lower()
    user = await db.scalar(
        select(User).where(or_(User.email == identifier, User.phone == payload.identifier.strip()))
    )
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_access_token(subject=str(user.user_id), role=user.role.value)
    return AuthResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)
