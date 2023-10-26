from typing import Annotated

from fastapi import FastAPI, Header

from fastapi_cors import CORS

from datetime import datetime, timedelta

from payloads import GenerateTokenPayload

from github_fine_grained_token_client import (
    BlockingPromptTwoFactorOtpProvider,
    GithubCredentials,
    SelectRepositories,
    async_client,
)

app = FastAPI()

app.add_middleware(
    CORS,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def status():
    return {"status": "okay"}


@app.post("/tokens/generate")
async def generate_tokens(
    payload: GenerateTokenPayload,
    token: Annotated[str | None, Header(convert_underscores=False)] = None,
):
    try:
        token_splitted = token.split(":")

        assert len(token_splitted) == 2

        username = token_splitted[0]

        password = token_splitted[1]

        credentials = GithubCredentials(username, password)

        assert credentials.username and credentials.password

        async with async_client(
            credentials=credentials,
            two_factor_otp_provider=BlockingPromptTwoFactorOtpProvider(),
        ) as session:
            expires_at = datetime.now() + timedelta(days=364)

            token = await session.create_token(
                payload.token_name,
                expires=expires_at,
                scope=SelectRepositories([payload.repository_name]),
            )

        return {
            "token": token,
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S %p"),
        }
    except Exception as e:
        return {"error": str(e)}
