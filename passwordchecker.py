import requests
'''
allows requests, like having a browser without the browser, manually request data
'''
import hashlib  # for hashing


def request_api_data(query_char):  # contacts password DBs, query_char is our pw  first 5 character hash
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)  # response from url, meant to contain a list of password hashes, their tails
    if res.status_code != 200:  # if there's a communication error between PC and password DB
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res  # returns the list of tails hashes and their counts


def get_password_leaks_count(hashes, hash_to_check):  # compares the tail hash list with our password tail hash
    hashes = (line.split(':') for line in hashes.text.splitlines())
    '''
    1: splitlines() => returns list of hash:count
    2: split() => turns hash:count into [hash, count]
    3: hashes is list of [hash, count]
    '''
    # for loop that traverses through the tail hash list
    for hash, count in hashes:  # variable named hash is the [tail hash, count]
        if hash == hash_to_check:  # if a tail hash in list matches our password tail hash
            return count  # return number of password leak times
    return 0


def pwned_api_check(password):  # check password if exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # prepare the password hash with SHA1
    '''
    1: password.encode('utf-8') => encode password in utf-8, encoding is a must
    2: hashlib.sha1() => run password through SHA1 hashing algorithm
    3: .hexdigest() => hash object returned as string object 2x long made of hexadecimal digits
    4: .upper() => for compatibility with API, hash must be converted to uppercase
    '''
    # prepare sections of the hashed password
    first5_char = sha1password[:5]  # first 5 characters of hashed password, index 0 to 4
    tail = sha1password[5:]  # remaining characters of hashed pw, index 5 to the end

    # send to API, the first 5 characters of the uppercase hashed password,
    # store results (list of password tail hashes) in response variable
    response = request_api_data(first5_char)  # will contain list of tail hashes and their leak count, hash:count

    return get_password_leaks_count(response, tail)


def main(password):
    count = pwned_api_check(password)
    if count:
        print(f'{password} was found {count} times... you should probably change your password!')
    else:
        print(f'{password} was NOT found. Carry on!')
    return 'done!'


print("                 PASSWORD CHECKER                       ")
print("This program checks if a password has been leaked / cracked or not")
password = input("Please enter a password you would like to text: ")
main(password)
