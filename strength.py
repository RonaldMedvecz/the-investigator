password = input("Enter a password: ")

has_length = len(password) >= 8
has_numbers = any(c.isdigit() for c in password)
has_symbols = any(not c.isalnum() for c in password)
has_caps = any(c.isupper() for c in password)

score = sum([has_length, has_numbers, has_symbols, has_caps])

if score <= 1:
    rating = "Weak"
elif score <= 3:
    rating = "Medium"
else:
    rating = "Strong"

print(f"Your password strength: {rating}. Thanks for checking!")
