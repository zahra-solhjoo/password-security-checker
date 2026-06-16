import re
import getpass

def check_password_strength(username, password, birth_year):
    """
    Check password strength based on 8 main security filters + birth year warning.
    """
    score = 8  # Initial score (for 8 main filters)
    reasons = []  # List of reasons for score deduction (Weaknesses)
    strengths = [] # List of passed filters (Strengths)
    warnings = []  # List of warnings (non-score affecting, e.g., birth year)

    # Prepare username formats for comparison
    username_lower = username.lower()
    username_swap = username.swapcase()
    
    # Dictionary for character substitution mapping
    substitution_map = {
        '@': 'a',
        '!': 'i',
        '$': 's',
        '0': 'o'
    }
    
    # Helper function to normalize password by replacing special chars with standard letters
    def normalize_password(pwd):
        normalized = pwd.lower()
        for char, replacement in substitution_map.items():
            normalized = normalized.replace(char, replacement)
        return normalized

    # --- Filter 1: Password length greater than 8 characters ---
    if len(password) > 8:
        strengths.append("Password length is sufficient (more than 8 characters).")
    else:
        score -= 1
        reasons.append("Password length must be greater than 8 characters.")

    # --- Filter 2: Must contain at least one English letter ---
    if re.search(r"[a-zA-Z]", password):
        strengths.append("Contains at least one English letter.")
    else:
        score -= 1
        reasons.append("Password must contain at least one English letter.")

    # --- Filter 3: Must contain at least one special character ($, !, @) ---
    if re.search(r"[$!@]", password):
        strengths.append("Contains at least one special character ($, !, @).")
    else:
        score -= 1
        reasons.append("Password must contain at least one special character from ($, !, @).")

    # --- Filter 4: Must contain at least one uppercase English letter ---
    if re.search(r"[A-Z]", password):
        strengths.append("Contains at least one uppercase English letter.")
    else:
        score -= 1
        reasons.append("Password must contain at least one uppercase English letter.")

    # --- Filter 5: Password must not be exactly the same as username ---
    if password != username:
        strengths.append("Password is not identical to the username.")
    else:
        score -= 1
        reasons.append("Password cannot be exactly the same as the username.")

    # --- Filter 6: Password must not be the SwapCase version of the username ---
    if password != username_swap:
        strengths.append("Password does not simply swap case of the username.")
    else:
        score -= 1
        reasons.append("Password cannot be the SwapCase version of the username.")

    # --- Filter 7: Password must not be the username with substituted special characters ---
    normalized_pass = normalize_password(password)
    if normalized_pass != username_lower:
        strengths.append("Password is not the username with substituted special characters.")
    else:
        score -= 1
        reasons.append("Password cannot be the username with substituted special characters (e.g., @ for a).")

    # --- Filter 8: Password must not be a common/weak password ---
    common_passwords = [
        "123456", "12345678", "12345", "111111", "123456789", 
        "qwerty", "asdfgh", "zxcvbnm", "password", "admin", "P@s$w0rd"
    ]
    if password not in common_passwords:
        strengths.append("Password is not a common/weak password.")
    else:
        score -= 1
        reasons.append("Password is from the list of common/weak passwords.")

    # --- Filter: Birth Year Check (Warning Only, No Score Deduction) ---
    if birth_year and str(birth_year) in password:
        warnings.append("Warning: Using your birth year in the password is not recommended.")
    else:
        strengths.append("Birth year is not used in the password.")

    return score, reasons, strengths, warnings

def get_security_level(score):
    """
    Determine security level based on final score (out of 8).
    """
    if score == 8:
        return "Very Strong"
    elif score >= 6:
        return "Strong"
    elif score >= 4:
        return "Medium"
    elif score >= 2:
        return "Weak"
    else:
        return "Very Weak"

def main():
    print("=== Password Security Check ===")
    
    # Get username
    username = input("Please enter your username: ")
    
    # Get birth year
    try:
        birth_year = int(input("Please enter your birth year (e.g., 1370): "))
    except ValueError:
        print("Note: Invalid birth year entered. Birth year check will be skipped.")
        birth_year = ""

    # Get password securely (hidden input)
    try:
        password = getpass.getpass("Please enter your password: ")
    except Exception:
        print("Note: Secure input is not supported in this environment. Please enter your password (it may be visible).")
        password = input("Password: ")

    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return

    final_score, failed_filters, passed_filters, warnings = check_password_strength(username, password, birth_year)
    security_level = get_security_level(final_score)

    # Display Results
    print("\n" + "="*45)
    print(f"Final Score: {final_score} out of 8")
    print(f"Security Level: {security_level}")
    
    if passed_filters:
        print("\nStrengths (Passed Filters):")
        for strength in passed_filters:
            print(f"  ✔ {strength}")
    
    if failed_filters:
        print("\nWeaknesses (Failed Filters - Score Deduction):")
        for i, reason in enumerate(failed_filters, 1):
            print(f"  ✖ {reason}")
            
    if warnings:
        print("\nSecurity Warnings (No Score Deduction):")
        for warning in warnings:
            print(f"  ⚠ {warning}")
    
    print("="*45)

if __name__ == "__main__":
    main()