import pyotp

from github_fine_grained_token_client import TwoFactorOtpProvider


class BlockingPromptTwoFactorOtpProvider(TwoFactorOtpProvider):
    def __init__(self, totp_key) -> None:
        self.totp_key = totp_key

    async def get_otp_for_user(self, username: str) -> str:
        return pyotp.TOTP(self.totp_key).now()
