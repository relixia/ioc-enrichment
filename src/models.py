from sqlalchemy import create_engine, Column, String, Boolean, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

Base = declarative_base()

# Load environment variables from the .env file
envs_path = os.path.join(os.path.dirname(__file__), "../envs/.env")
load_dotenv(dotenv_path=envs_path)

# Access the environment variables
DATABASE_HOST = os.getenv("POSTGRES_USER")
DATABASE_PASSWORD = os.getenv("POSTGRES_PASSWORD") 
DATABASE_DB = os.getenv("POSTGRES_DB")

database_uri = f"postgresql://{DATABASE_HOST}:{DATABASE_PASSWORD}@db:5432/{DATABASE_DB}"
engine = create_engine(database_uri)
print("Creating tables...")
Base.metadata.create_all(engine)
print("Tables created.")
Session = sessionmaker(bind=engine)


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True)
    ioc = Column(String)
    ioc_type = Column(String)
    virustotal = Column(String, default="No data from this service")
    ipinfo = Column(String, default="No data from this service")
    abuseipdb = Column(String, default="No data from this service")
    greynoise = Column(String, default="No data from this service")
    opswat = Column(String, default="No data from this service")
    opswat_file_reputation = Column(String, default="No data from this service")
    kaspersky = Column(String, default="No data from this service")
    hybrid_analysis = Column(String, default="No data from this service")
    urlscanio = Column(String, default="No data from this service")
    criminalip = Column(String, default="No data from this service")
