import secrets
import os

def generate_secret_key(length=32):
    """Generate a secure random hex string for Flask SECRET_KEY."""
    return secrets.token_hex(length)

def update_env_file(key, value, env_file=".env"):
    """Append or update a key-value pair in the .env file."""
    env_lines = []
    key_exists = False

    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            env_lines = f.readlines()
            for i, line in enumerate(env_lines):
                if line.startswith(f"{key}="):
                    env_lines[i] = f"{key}={value}\n"
                    key_exists = True
                    break

    if not key_exists:
        env_lines.append(f"{key}={value}\n")

    with open(env_file, "w") as f:
        f.writelines(env_lines)

if __name__ == "__main__":
    secret_key = generate_secret_key(32)
    print(f"Generated SECRET_KEY: {secret_key}")
    try:
        update_env_file("SECRET_KEY", secret_key)
        print(f"Updated .env file with SECRET_KEY")
    except Exception as e:
        print(f"Failed to update .env file: {str(e)}")