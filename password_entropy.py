"""
Leif Gregory <leif@devtek.org>
Calculate bits of entropy for passwords, cracking time, and check if password has been breached
Tested to Python v3.11.6

Changelog
20240322 -  Added Moore's law alt calc and fixed some bone-headed math mistakes
20240321 -  Added haveibeenpwned.com API check
20240320 -  Added get_crack_time function
20240308 -  Initial Code

Usage: python3 password_entropy.py [password]
- If a password is provided as an argument, it will return entropy value
- If no password is provided, it will prompt for password variables and return entropy value

Scale assumes anything less than 60 bits entropy is a weak password.
- 9 character password with lower & upper & digit & symbol chars
- 10 character password with lower & upper chars
- 10 character password with (lower | upper) & (digit | symbol) chars
- 11 character password with lower | upper | digit | symbol chars
- 11 character password with (lower | upper | symbol) & digit chars

Entropy bits for single character:
lower | upper: 4.70 bits
lower | upper & digit: 5.17 bits
digit & symbol: 5.39 bits
lower & upper: 5.70 bits
lower | upper & symbol: 5.86 bits
lower & upper & digit: 5.95 bits
lower & upper & digit & symbol: 6.55 bits

Formula: E = log₂(Pᴸ) or can also be done as E = L * log₂(P)
E = Entropy in bits
L = Character length of password
P = Pool of characters 
    - Lowercase: 26 chars
    - Uppercase: 26 chars
    - Digits: 10 chars
    - Special: 32 chars
    - At least one of each of the above: 94 chars

www.pwnedpasswords.com API: 
https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import hashlib
import math
import requests
import sys
import time
from decimal import Decimal


def get_crack_time(pool, length, current_gps):
    """
    Determine how long it would take to crack a password based on
    varying number of guesses per second.

    Parameters
    ----------
    pool : int
    length: int

    Returns
    -------
    dict : element 1: guesses/s, element 2: time to crack
    """

    # As of 20240308, the fastest cracking rig was capable of 2.7 trillion gps 
    # and is represented as the last number in the gps list below. See global
    # variable current_gps below imports.
    gps = [10_000, 5_000_000, 250_000_000_000, 1_000_000_000_000, current_gps]  # Guesses per second
    magnitudes = [(1_000_000_000_000_000_000, "∞ years"), (1_000_000_000_000_000, "quintillion years"), (1_000_000_000_000, "trillion years"), (1_000_000_000, "billion years"), (1_000_000, "million years"), (10_000, "thousand years"), (1, "years")]
    neg_magnitudes = [(.1, "months"), (.01, "days"), (.001, "hours"), (.0001, "minutes"), (.00001, "seconds"), (.000001, "less than a second")]
    crack_time = {}

    for guess in gps:
        # More traditional method based on current day compute power and
        # how long it would take to crack the password.
        time_to_crack = (((pool**length) / guess))  # In seconds

        # seconds = time_to_crack
        # minutes = time_to_crack / 60
        # hours = time_to_crack / 3600
        # days = time_to_crack / 86400
        # weeks = time_to_crack / 604800
        # months = time_to_crack / 2628000
        years = time_to_crack / 31536000

        if years >= 1:
            for i in range(len(magnitudes)):
                if years >= magnitudes[i][0]:
                    crack_time[f'{int(guess):,}/s'] = "∞ years" if magnitudes[i][1] == "∞ years" else f'{(int(years)/magnitudes[i][0]):.2f} {magnitudes[i][1]}'
                    break
        else:
            for i in range(len(neg_magnitudes)):
                if years >= neg_magnitudes[i][0]:
                    crack_time[f'{int(guess):,}/s'] = "less than a second" if neg_magnitudes[i][1] == "less than a second" else f'{(years/neg_magnitudes[i][0]):.2f} {neg_magnitudes[i][1]}'
                    break

    return crack_time


def get_request(url, parameters=None):
    """
    Makes requests more resillient to timeouts and failed connections

    Parameters
    ----------
    url : string
    parameters : dict

    Returns
    -------
    var : Response from API, could be text, could be json
    """

    try:
        response = requests.get(url=url, params=parameters, timeout=2)
    except:
        for i in range(5, 0, -1):
            print(f'Connection Error. Waiting... ({i})', end='\r')
            time.sleep(1)
        print('Retrying.' + ' '*50, end='\r')

        # recusively try again
        return get_request(url, parameters)

    if response:
        return response
    elif response.status_code == 404:
        return response
    else:
        for i in range(10, 0, -1):
            print(f'No response, waiting 10 seconds... ({i})' + ' '*10, end='\r')
            time.sleep(1)
        print('Retrying.' + ' '*50, end='\r')

        # recusively try again
        return get_request(url, parameters)


def get_strength(entropy_bits):
    """
    Return a strength score based on entropy value

    Parameters
    ----------
    entropy_bits : float

    Returns
    -------
    string : Weak, Normal, Important, Critical
    """

    entropy_bits = round(entropy_bits)
    strengths = [(100, 'Critical'), (80, 'Important'), (60, 'Normal'), (0, 'Weak')]
    
    # Iteratively tests entropy_bits >= 100, then >=80, then >= 60, then >=0
    # Once a test is True, returns the string value
    for i in range(len(strengths)):
        if entropy_bits >= strengths[i][0]:
            return strengths[i][1]


if __name__ == "__main__":
    # Var to indicate today's fastest cracking rig as guesses
    # per second (gps)
    current_gps = 2.7e+12  # 2.7 trillion gps

    if len(sys.argv) > 1:  # looking for a password as an argument
        lowercase = 0
        uppercase = 0
        digits = 0
        symbols = 0
        symbolchars = "`~!@#$%^&*()-_=+[{]}\\|;:'\"/?,<.>"  # 32 symbols

        password = sys.argv[1]
        length = len(password)

        for x in password:
            digits = 10 if x.isdigit() else digits
            lowercase = 26 if x.islower() else lowercase
            uppercase = 26 if x.isupper() else uppercase
            symbols = 32 if x in symbolchars else symbols

    else:  # No password given, prompt for password variables
        length = int(input("Password Length: "))
        lowercase = 26 if input("Include Lowercase (y/n): ").lower() == "y" else 0
        uppercase = 26 if input("Include Uppercase (y/n): ").lower() == "y" else 0
        digits = 10 if input("Include Digits (y/n): ").lower() == "y" else 0
        symbols = 32 if input("Include Symbols (y/n): ").lower() == "y" else 0

    pool = lowercase + uppercase + digits + symbols
    entropy = math.log2(pool**length)

    print(f"\nEntropy: {entropy:.2f} bits - Use Case: {get_strength(entropy)} account password")

    if password is not None:
        count = None
        base_url = "https://api.pwnedpasswords.com/range/"
        hash = hashlib.sha1(password.encode())
        
        response = get_request(f"{base_url}{hash.hexdigest()[:5]}")  # Send only first 5 chars of hash per API
        if response.status_code == 200:
            r = response.text
            hashes = r.split("\r\n")  # Hash suffixes (minus first five chars) returned one per line as a string

            for i in range(len(hashes)):
                if hash.hexdigest().upper()[5:] in hashes[i]:  # Search for hash minus the first five chars
                    hash_split = hashes[i].split(':')  # Format SHA1_HASH_SUFFIX:COUNT
                    count = hash_split[1]  # Get the number of breaches the password has appeared in

            if count is not None:
                print(f"\nWARNING: {password} is listed in the haveibeenpwned.com database from {f'{int(count):,}'} breaches!")

    print(f"\nWorst case (for hacker) to crack your password at various guesses per second.")

    crack_time = get_crack_time(pool, length, current_gps)

    cw = 25  # Column width for displayed output
    for k, v in crack_time.items():
        print(f"{k:<{cw}} {v:<{cw}}")

    print(f"\nMoore's law method: How many years until a rig can generate enough guesses per\nsecond to crack the password in one hour.")

    # Alternative method based on Moore's law to get to a processing point
    # in years where the password could be cracked in under an hour. The article
    # was written in 2019 and assumed a current gps of 10⁹ whereas at the time of
    # writing this script it is 2.7 x 10¹². I have adjusted the calculation below
    # to account for that using the current_gps variable. 
    # https://www.scientificamerican.com/article/the-mathematics-of-hacking-passwords/
    
    # time_to_crack_alt = 2 * math.log2((pool**length) / (current_gps * 3600))

    # After running a number of simulations, the math here is roughly off by a 
    # factor of two when compared to straight password space / gps. So, I had a 
    # nice long conversation with ChatGPT to come up with a better formula
    # which is below.

    permutations_per_hour = pool**length / 3600
    guesses_per_second_required = permutations_per_hour / 3600
    time_to_crack_alt = math.log2(guesses_per_second_required / current_gps) / math.log2(2)

    # At any rate, I thought it was a more interesting calculation than the standard
    # pool**length / gps, but understand that while Moore's Law states that the
    # number of transistors on an IC will double every year, and it's been accurate
    # so far, it does not necessarily coorelate with doubling the gps capability as
    # well. I just thought it'd be fun to throw in here for comparison sake.

    if time_to_crack_alt < 0:
        alt_years = "Can already be cracked in less than an hour"
    elif 0 < time_to_crack_alt <= 1:
        alt_years = "1 year or less"
    else:
        alt_years = f"{time_to_crack_alt:.2f} years"

    print(alt_years)
