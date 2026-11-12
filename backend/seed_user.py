from core.database import SessionLocal
from core.security import hash_password
from models.User import User

def seed():
    db = SessionLocal()
    email = "admin@example.com"
    password = "AdminPassword123"
    
    existing = db.query(User).filter(User.email == email).first()
    if not existing:
        user = User(
            email=email,
            hashed_password=hash_password(password),
            is_active=True
        )
        db.add(user)
        db.commit()
        print(f"Created default user: {email} / {password}")
    else:
        print(f"User {email} already exists.")
    db.close()

if __name__ == "__main__":
    seed()
