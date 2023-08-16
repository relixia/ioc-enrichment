import os

from dotenv import load_dotenv
from sqlalchemy import Boolean, Column, Enum, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from enums import InputType

Base = declarative_base()

envs_path = os.path.join(os.path.dirname(__file__), "../envs/.env")
load_dotenv(dotenv_path=envs_path)

DATABASE_HOST = os.getenv("POSTGRES_USER")
DATABASE_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DATABASE_DB = os.getenv("POSTGRES_DB")

database_uri = f"postgresql://{DATABASE_HOST}:{DATABASE_PASSWORD}@db:5432/{DATABASE_DB}"
engine = create_engine(database_uri)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True)
    ioc = Column(String)
    ioc_type = Column(Enum(InputType))
    virustotal = Column(String, default="No data from this service")
    kaspersky = Column(String, default="No data from this service")
    ipqualityscore = Column(String, default="No data from this service")
    ipinfo = Column(String, default="No data from this service")
    abuseipdb = Column(String, default="No data from this service")
    greynoise = Column(String, default="No data from this service")
    opswat = Column(String, default="No data from this service")
    opswat_file_reputation = Column(String, default="No data from this service")
    hybrid_analysis = Column(String, default="No data from this service")
    urlscanio = Column(String, default="No data from this service")
    criminalip = Column(String, default="No data from this service")
    cloudflare = Column(String, default="No data from this service")
    iplocation = Column(String, default="No data from this service")
    urlhaus = Column(String, default="No data from this service")
    phishtank = Column(String, default="No data from this service")
    usom = Column(String, default="No data from this service")
    openphish = Column(String, default="No data from this service")
    shodan = Column(String, default="No data from this service")
    abstract_email = Column(String, default="No data from this service")
    hunterio = Column(String, default="No data from this service")
    cloudflare_email = Column(String, default="No data from this service")
