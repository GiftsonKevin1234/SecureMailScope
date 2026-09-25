import smtplib
import ssl
from email.mime.text import MIMEText

server = smtplib.SMTP("127.0.0.1", 587)
server.set_debuglevel(1)

server.ehlo()
print("Starting TLS...")
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
server.starttls(context=context)
server.ehlo()

msg = MIMEText("This is a test email for SecureMailScope PCAP capture.")
msg["Subject"] = "Test STARTTLS Email"
msg["From"] = "test@test.local"
msg["To"] = "test@test.local"

server.login("test@test.local", "test123")
server.sendmail("test@test.local", "test@test.local", msg.as_string())
print("Email sent successfully!")

server.quit()