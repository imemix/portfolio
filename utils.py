import base64

DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1395890455643684964/bykCWFWIPxAqWMTAYM0dyaHEegbX0nTaa7Aco2Bb9VweF2NIjesvaB9ASjGTBfiZY85k'

def encrypt_message(message: str) -> str:
    # Simple base64 encoding as "encryption"
    encoded_bytes = base64.b64encode(message.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def decrypt_message(encoded: str) -> str:
    # Simple base64 decoding
    decoded_bytes = base64.b64decode(encoded.encode('utf-8'))
    return decoded_bytes.decode('utf-8')

def discord_decrypt_command(encoded: str) -> str:
    """
    Utility for Discord: paste the encoded string and get the decoded message.
    Usage: Call this function with the encrypted string from Discord.
    """
    try:
        return decrypt_message(encoded)
    except Exception as e:
        return f"Error decoding: {e}"

def auto_decrypt_discord_message(content: str) -> str:
    """
    Automatically detect and decrypt base64-encoded messages in Discord bot.
    Returns the decrypted message if possible, else returns the original content.
    """
    try:
        # Optionally, add logic to detect if content is base64
        # For now, just try to decode
        return decrypt_message(content)
    except Exception:
        return content