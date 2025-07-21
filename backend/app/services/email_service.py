from fastapi import BackgroundTasks

from app.models.models import Users

USER_VERIFY_ACCOUNT = "verify-account"
FORGOT_PASSWORD = "password-reset"

async def send_account_verification_email(user: Users, background_task: BackgroundTasks):
    string_context = user.get_context_string(context=USER_VERIFY_ACCOUNT)