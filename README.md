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

## Example
**python3 ../password_entropy.py P@55w0rd#$**

## Result
Entropy: 56.41 bits - Use Case: Weak account password

Worst case (for hacker) to crack your password at various guesses per second.
10,000/s                  30.26 thousand years     
5,000,000/s               605.00 years             
250,000,000,000/s         1.21 days                
1,000,000,000,000/s       3.03 hours               
2,700,000,000,000/s       1.12 hours               

Moore's law method: How many years until a rig can generate enough guesses per 
second to crack the password in one hour.

5.30 years
