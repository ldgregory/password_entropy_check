# Password Entropy Check
Calculates password entropy, time to crack and if / how many times the password was discovered in a breach via the HaveIBeenPwned.com API.

Usage: **python3 password_entropy.py [password]**
- If a password is provided as an argument, it will return entropy value
- If no password is provided, it will prompt for password variables and return entropy value

Scale assumes anything less than 60 bits entropy is a weak password.
- 9 character password with lower & upper & digit & symbol chars
- 10 character password with lower & upper chars
- 10 character password with (lower | upper) & (digit | symbol) chars
- 11 character password with lower | upper | digit | symbol chars
- 11 character password with (lower | upper | symbol) & digit chars

Entropy bits for single character:
- lower | upper: 4.70 bits
- lower | upper & digit: 5.17 bits
- digit & symbol: 5.39 bits
- lower & upper: 5.70 bits
- lower | upper & symbol: 5.86 bits
- lower & upper & digit: 5.95 bits
- lower & upper & digit & symbol: 6.55 bits

Formula: E = log₂(Pᴸ) or can also be done as E = L * log₂(P)

- E = Entropy in bits
- L = Character length of password
- P = Pool of characters 
    - Lowercase: 26 chars
    - Uppercase: 26 chars
    - Digits: 10 chars
    - Special: 32 chars
