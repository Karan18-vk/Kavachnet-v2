# Backend/utils/validators.py

import re

# Strict RFC 5322 compliant regex for robust email validation
_EMAIL_REGEX = re.compile(
    r"^(?!\.)(?!.*\.\.)([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,})$"
)

def validate_email_strict(email: str) -> bool:
    """
    Performs zero-trust runtime validation on recipient email addresses.
    Rejects malformed structures explicitly to prevent SMTP injection or parser crashes.
    """
    if not email or not isinstance(email, str):
        return False
        
    email = email.strip()
    if len(email) > 254:  # RFC 5321 length constraint
        return False
        
    if not _EMAIL_REGEX.match(email):
        return False
        
    return True
