from typing import Annotated

from fastapi import FastAPI, Header

from datetime import datetime, timedelta

from payloads import GenerateTokenPayload

from github_fine_grained_token_client import (
    GithubCredentials,
    SelectRepositories,
    async_client,
)

from tfa import BlockingPromptTwoFactorOtpProvider

app = FastAPI()


@app.get("/")
async def status():
    return {"status": "okay"}


@app.post("/tokens/generate")
async def generate_tokens(
    payload: GenerateTokenPayload,
    username_password: Annotated[str | None, Header(convert_underscores=False)] = None,
):
    try:
        username_password_splitted = username_password.split(":")

        assert len(username_password_splitted) == 2

        credentials = GithubCredentials(
            username_password_splitted[0], username_password_splitted[1]
        )

        assert credentials.username and credentials.password

        async with async_client(
            credentials=credentials,
            two_factor_otp_provider=BlockingPromptTwoFactorOtpProvider(
                payload.totp_key
            ),
        ) as session:
            expires_at = datetime.now() + timedelta(days=364)

            token = await session.create_token(
                name=payload.token_name,
                expires=expires_at,
                scope=SelectRepositories([payload.repository_name]),
            )

        return {
            "token_name": payload.token_name,
            "repository_name": payload.repository_name,
            "token": token,
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S %p"),
        }
    except Exception as e:
        return {"error": str(e)}
