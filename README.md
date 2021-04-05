## Hacking Json Web Token Signature.

### Description.
This repository contains a series of APIs that are vulnerable to the following JWT signature attacks:
  -	none
  -	weak secret key
  -	key confusion
  -	key injection
  -	jwks spoofing
  -	kid

Each API is vulnerable to a specific attack and they are meant only for you to practice JWT attacks, therefore, there is not protection in place for any kind of attack you might like to launch at them.
You do not need to look into the code to solve these challenges, however, you are very welcome to do so to further your understanding of these vulnerabilities.

### Instructions.
#### Running the APIs
1. They run on linux and you need to install `Node.js` and `openssl`
2. The directory `jwt-signature-apis-challenges` contains the application with the APIs for the challenges.
3. Go into the directory `jwt-signature-apis-challenges` and install the dependencies with the command `sudo npm install`
4. Run the application with `sudo node app.js` (it runs on port 443)

#### Postman file
There is Postman file to help you starting with the APIs, follow these steps:
  1. Import the file into [Postman](https://www.postman.com/)
  2. Disable TLS/SSL verification on postman. The APIs use a self-signed x509 certificate.
  3. There are 6 directories, each one for an specific JWT attack
  4. Inside each directory, there are 2 APIs.
    - One named <attack>-obtain-token that returns an JWT and an endpoint. This endpoint is the URI where you should direct your tampered jwt to.
    - The other API is named <attack>-send-token it already contains  the endpoint mentioned in <attack>-obtain-token and you should use it to verify whether you were successful in your attack with your tampered token.
    - Modify the given token, resign and send it. If you tampered token gets a Congrats!! response then you succeeded.
    - All the JWT vulnerabilities showed in this repository are for JWT verification bypass. The API containing the JWT kid attack is not.
    - If you like to see how a successful response to your attack looks like just send the same token you got from <attack>-obtain-token (As this is a valid token you should get a congrats reply)
### Tool to automate JWT attacks
- [The Json Web Token Toolkit](https://github.com/ticarpi/jwt_tool)
#### References
- [JWT Introduction](https://jwt.io/introduction/)
- [Methodology to attack JWTs](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
