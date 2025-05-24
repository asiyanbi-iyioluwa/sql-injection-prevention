import smtplib

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login("asiyanbiiyioluwa@gmail.com", "lnnhichtknzufbxg")
        print("Login successful!")
except Exception as e:
    print(f"Login failed: {e}")
