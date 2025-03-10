import os
import bcrypt

from datetime import datetime, timedelta, timezone

from dateutil.relativedelta import relativedelta
from sqlalchemy import Column, VARCHAR, CHAR, ForeignKey, TIMESTAMP, update, and_, inspect, text, String, DateTime
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import declarative_base, Session

from util import NV

Base = declarative_base()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import Engine



db = create_engine(os.getenv('DATABASE'), echo=True, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db)

def get_db():
    """Функция для получения сессии БД с автоматическим закрытием"""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Users(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)  # UUID
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)  # Здесь должен быть захешированный пароль

class RefreshTokens(Base):
    __tablename__ = "refresh_tokens"


    token = Column(String, primary_key=True, unique=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

class Origin(Base):
    __tablename__ = "origin"

    origin_ref = Column(CHAR(length=36), primary_key=True, unique=True, index=True)  # uuid4
    hostname = Column(VARCHAR(length=256), nullable=True)
    guest_driver_version = Column(VARCHAR(length=10), nullable=True)
    os_platform = Column(VARCHAR(length=256), nullable=True)
    os_version = Column(VARCHAR(length=256), nullable=True)

    def __repr__(self):
        return f'Origin(origin_ref={self.origin_ref}, hostname={self.hostname})'

    def serialize(self) -> dict:
        return {
            "origin_ref": self.origin_ref,
            "hostname": self.hostname,
            "guest_driver_version": self.guest_driver_version,
            "os_platform": self.os_platform,
            "os_version": self.os_version,
        }

    @staticmethod
    def create_statement(engine: Engine):
        """Генерация SQL-запроса для создания таблицы"""
        from sqlalchemy.schema import CreateTable
        return CreateTable(Origin.__table__).compile(engine)

    @staticmethod
    def create_or_update(db: Session, origin: "Origin"):
        """Создает или обновляет запись в таблице Origin"""
        entity = db.query(Origin).filter(Origin.origin_ref == origin.origin_ref).first()
        if entity is None:
            db.add(origin)
        else:
            db.query(Origin).filter(Origin.origin_ref == origin.origin_ref).update({
                "hostname": origin.hostname,
                "guest_driver_version": origin.guest_driver_version,
                "os_platform": origin.os_platform,
                "os_version": origin.os_version,
            })
        db.commit()

    @staticmethod
    def delete(db: Session, origin_refs: list[str] = None) -> int:
        """Удаляет указанные Origin или все записи"""
        if origin_refs is None:
            deletions = db.query(Origin).delete()
        else:
            deletions = db.query(Origin).filter(Origin.origin_ref.in_(origin_refs)).delete()
        db.commit()
        return deletions

    @staticmethod
    def delete_expired(db: Session) -> int:
        """Удаляет записи Origin, которые больше не связаны с Lease"""
        from orm import Lease  # Импортируем здесь, чтобы избежать циклических импортов
        expired_origins = db.query(Origin).outerjoin(Lease, Origin.origin_ref == Lease.origin_ref).filter(
            Lease.lease_ref.is_(None)
        ).all()
        origin_refs = [origin.origin_ref for origin in expired_origins]
        deletions = db.query(Origin).filter(Origin.origin_ref.in_(origin_refs)).delete()
        db.commit()
        return deletions


class Lease(Base):
    __tablename__ = "lease"

    lease_ref = Column(CHAR(length=36), primary_key=True, nullable=False, index=True)
    origin_ref = Column(CHAR(length=36), ForeignKey("origin.origin_ref", ondelete="CASCADE"), nullable=False, index=True)
    lease_created = Column(TIMESTAMP(), nullable=False)
    lease_expires = Column(TIMESTAMP(), nullable=False)
    lease_updated = Column(TIMESTAMP(), nullable=False)

    def __repr__(self):
        return f'Lease(origin_ref={self.origin_ref}, lease_ref={self.lease_ref}, expires={self.lease_expires})'

    def serialize(self, renewal_period: float, renewal_delta: timedelta) -> dict:
        lease_renewal = int(Lease.calculate_renewal(renewal_period, renewal_delta).total_seconds())
        lease_renewal = self.lease_updated + relativedelta(seconds=lease_renewal)

        return {
            "lease_ref": self.lease_ref,
            "origin_ref": self.origin_ref,
            "lease_created": self.lease_created.replace(tzinfo=timezone.utc).isoformat(),
            "lease_expires": self.lease_expires.replace(tzinfo=timezone.utc).isoformat(),
            "lease_updated": self.lease_updated.replace(tzinfo=timezone.utc).isoformat(),
            "lease_renewal": lease_renewal.replace(tzinfo=timezone.utc).isoformat(),
        }

    @staticmethod
    def create_or_update(db: Session, lease: "Lease"):
        """Создает или обновляет запись в таблице Lease"""
        entity = db.query(Lease).filter(Lease.lease_ref == lease.lease_ref).first()
        if entity is None:
            if lease.lease_updated is None:
                lease.lease_updated = lease.lease_created
            db.add(lease)
        else:
            db.query(Lease).filter(Lease.lease_ref == lease.lease_ref).update({
                "origin_ref": lease.origin_ref,
                "lease_expires": lease.lease_expires,
                "lease_updated": lease.lease_updated,
            })
        db.commit()

    @staticmethod
    def find_by_origin_ref(db: Session, origin_ref: str) -> list["Lease"]:
        """Находит все записи Lease по origin_ref"""
        return db.query(Lease).filter(Lease.origin_ref == origin_ref).all()

    @staticmethod
    def find_by_lease_ref(db: Session, lease_ref: str) -> "Lease":
        """Находит запись Lease по lease_ref"""
        return db.query(Lease).filter(Lease.lease_ref == lease_ref).first()

    @staticmethod
    def find_by_origin_ref_and_lease_ref(db: Session, origin_ref: str, lease_ref: str) -> "Lease":
        """Находит запись Lease по origin_ref и lease_ref"""
        return db.query(Lease).filter(and_(Lease.origin_ref == origin_ref, Lease.lease_ref == lease_ref)).first()

    @staticmethod
    def renew(db: Session, lease: "Lease", lease_expires: datetime, lease_updated: datetime):
        """Обновляет lease_expires и lease_updated"""
        db.query(Lease).filter(
            and_(Lease.origin_ref == lease.origin_ref, Lease.lease_ref == lease.lease_ref)
        ).update({"lease_expires": lease_expires, "lease_updated": lease_updated})
        db.commit()

    @staticmethod
    def cleanup(db: Session, origin_ref: str) -> int:
        """Удаляет все lease, связанные с origin_ref"""
        deletions = db.query(Lease).filter(Lease.origin_ref == origin_ref).delete()
        db.commit()
        return deletions

    @staticmethod
    def delete(db: Session, lease_ref: str) -> int:
        """Удаляет lease по lease_ref"""
        deletions = db.query(Lease).filter(Lease.lease_ref == lease_ref).delete()
        db.commit()
        return deletions

    @staticmethod
    def delete_expired(db: Session) -> int:
        """Удаляет все просроченные lease"""
        deletions = db.query(Lease).filter(Lease.lease_expires <= datetime.now(timezone.utc)).delete()
        db.commit()
        return deletions

    @staticmethod
    def calculate_renewal(renewal_period: float, delta: timedelta) -> timedelta:
        """Рассчитывает время продления"""
        renew = delta.total_seconds() * renewal_period
        return timedelta(seconds=renew)

def init_db(engine):
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    existing_admin = session.query(Users).filter(Users.username == ADMIN_USERNAME).first()
    if not existing_admin:
        hashed_password = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
        admin_user = Users(id=ADMIN_USERNAME, username=ADMIN_USERNAME, password=hashed_password)
        session.add(admin_user)
        session.commit()

    session.close()


def migrate(engine: Engine):
    db = inspect(engine)

    def upgrade_1_0_to_1_1():
        x = db.dialect.get_columns(engine.connect(), Lease.__tablename__)
        x = next((_ for _ in x if _['name'] == 'origin_ref'), None)

        if x is None:
            print("Ошибка: Колонка 'origin_ref' не найдена в таблице 'lease'")
            return

        if x.get('primary_key', 0) > 0:
            print('Found old database schema with "origin_ref" as primary-key in "lease" table. Dropping table!')
            print('  Your leases are recreated on next renewal!')
            print('  If an error message appears on the client, you can ignore it.')
            Lease.__table__.drop(bind=engine)
            init_db(engine)

    # def upgrade_1_2_to_1_3():
    #    x = db.dialect.get_columns(engine.connect(), Lease.__tablename__)
    #    x = next((_ for _ in x if _['name'] == 'scope_ref'), None)
    #    if x is None:
    #        Lease.scope_ref.compile()
    #        column_name = Lease.scope_ref.name
    #        column_type = Lease.scope_ref.type.compile(engine.dialect)
    #        engine.execute(f'ALTER TABLE "{Lease.__tablename__}" ADD COLUMN "{column_name}" {column_type}')

    upgrade_1_0_to_1_1()
    # upgrade_1_2_to_1_3()
