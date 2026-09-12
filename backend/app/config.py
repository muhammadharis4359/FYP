import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./recon_mapper.db")

    SUBFINDER_TIMEOUT: int = int(os.getenv("SUBFINDER_TIMEOUT", "120"))
    AMASS_TIMEOUT: int = int(os.getenv("AMASS_TIMEOUT", "300"))
    HTTPX_TIMEOUT: int = int(os.getenv("HTTPX_TIMEOUT", "180"))
    GAU_TIMEOUT: int = int(os.getenv("GAU_TIMEOUT", "120"))
    NUCLEI_TIMEOUT: int = int(os.getenv("NUCLEI_TIMEOUT", "900"))


settings = Settings()
