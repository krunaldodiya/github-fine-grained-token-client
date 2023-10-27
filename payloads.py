from pydantic import BaseModel


class GenerateTokenPayload(BaseModel):
    repository_name: str
    token_name: str
    totp_key: str


class DeleteTokenPayload(BaseModel):
    token_name: str
    totp_key: str
