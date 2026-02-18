import asyncio
import sys
from pathlib import Path

from sqlalchemy import select

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.core.security import hash_password
from app.db.session import SessionLocal, init_db_schema
from app.models.enums import Role
from app.models.user import User


DEMO_USERS = [
    {
        "full_name": "Demo End User",
        "email": "user@ekyc.local",
        "phone": "9000000001",
        "password": "UserPass@123",
        "role": Role.user,
    },
    {
        "full_name": "Demo Reviewer",
        "email": "reviewer@ekyc.local",
        "phone": "9000000002",
        "password": "ReviewerPass@123",
        "role": Role.reviewer,
    },
    {
        "full_name": "Demo Admin",
        "email": "admin@ekyc.local",
        "phone": "9000000003",
        "password": "AdminPass@123",
        "role": Role.admin,
    },
]


async def seed_users() -> None:
    await init_db_schema()
    async with SessionLocal() as session:
        for item in DEMO_USERS:
            existing = await session.scalar(select(User).where(User.email == item["email"]))
            if existing is not None:
                continue

            user = User(
                full_name=item["full_name"],
                email=item["email"],
                phone=item["phone"],
                password_hash=hash_password(item["password"]),
                role=item["role"],
                is_verified=True,
            )
            session.add(user)

        await session.commit()


if __name__ == "__main__":
    asyncio.run(seed_users())
