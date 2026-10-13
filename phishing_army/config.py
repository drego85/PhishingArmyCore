from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    phishtank_token: str = ""
    stalkphish_token: str = ""
    urlscan_token: str = ""
    urlabuse_email: str = ""
    urlabuse_token: str = ""
    output_directory: Path = Path(".")


def load_settings() -> Settings:
    try:
        import Config  # type: ignore
    except ImportError:
        return Settings()
    return Settings(
        phishtank_token=getattr(Config, "phishtanktoken", "").strip(),
        stalkphish_token=getattr(Config, "stalkphishtoken", "").strip(),
        urlscan_token=getattr(Config, "urlscantoken", "").strip(),
        urlabuse_email=getattr(Config, "urlabuseemail", "").strip(),
        urlabuse_token=getattr(Config, "urlabusetoken", "").strip(),
        output_directory=Path(getattr(Config, "outputdirectory", ".") or "."),
    )
