# ExpirySense Pydantic Validation Models
from pydantic import BaseModel, Field
from typing import List

class HostnamesInput(BaseModel):
    """Requires bulk hostname parameters for real-time TLS analysis requests."""
    hostnames: List[str] = Field(
        ..., 
        description="List of target domains to verify, e.g. ['google.com', 'github.com']",
        example=["google.com", "github.com"]
    )
