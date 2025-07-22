
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import settings
from app.utils import email

USER_VERIFY_ACCOUNT = "verify-account"
FORGOT_PASSWORD = "password-reset"

async def send_account_verification_email(to_email: str, token: str):
    subject = "Verify Your DeadBox Account"
    verification_link = f"{settings.FRONTEND_URL}v1/auth/verify?token={token}"

    html = email.render_email_template("verify_email.html", context={'verification_link':verification_link})

    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['From'] = settings.EMAIL_FROM
    message['To'] = to_email
    message.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.EMAIL_FROM, settings.EMAIL_PASSWORD)
            server.send_message(message)
        print('email sent')
    except smtplib.SMTPAuthenticationError as e:
        print("Auth error:", e)
    except Exception as e:
        print(" Other error:", e)
            