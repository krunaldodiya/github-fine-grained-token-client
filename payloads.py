from pydantic import BaseModel


class GenerateTokenPayload(BaseModel):
    token_name: str
    repository_name: str
    totp_key: str
