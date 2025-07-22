import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import settings

USER_VERIFY_ACCOUNT = "verify-account"
FORGOT_PASSWORD = "password-reset"

async def send_account_verification_email(to_email: str, token: str):
    subject = "Verify Your Email"
    verification_link = f"{settings.FRONTEND_URL}v1/auth/verify?token={token}"


    html = f"""

    <html>
    <body>
    <p>Hi,</P><br>
    Click the link below to verify your email:<br>
    <a href="{verification_link}">{verification_link}</a>

    </body>
    </html>
"""
    
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
        print("Other error:", e)
            