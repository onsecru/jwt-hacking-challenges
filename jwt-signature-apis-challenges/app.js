const express = require("express");
const https = require('https');
const fs = require('fs');
const JWT = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request');
const { exec } = require('child_process');

const app = express();
app.use(express.json()); //midleware needed to handle post request

//Environment: Disable unauthorized x509 certificates. 
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

//JWT payload
const payload = { account: "Bob", role: "User" };

app.get("/", (req, res) => {
  res.status(200).json({ app: 'JWT Signature basic challenges.' });
});

app.post('/jwt/none', (req, res) => { //None endpoint
  const { jwt_token } = req.body;
  let secret_key = '';
  if (jwt_token == null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {
    const jwt_b64_dec = JWT.decode(jwt_token, { complete: true });
    if (jwt_b64_dec.header.alg == 'HS256') {
      secret_key = '885ae2060fbedcfb491c5e8aafc92cab5a8057b3d4c39655acce9d4f09280a20';
    } else if (jwt_b64_dec.header.alg == 'none') {
      secret_key = '';
    }
    JWT.verify(jwt_token, secret_key, { algorithms: ['none', 'HS256'], complete: true, audience: 'https://127.0.0.1/jwt/none' }, (err, decoded_token) => {
      if (err) {
        res.status(400).json(err);
      } else {
        const success = {
          message: 'Congrats!! You\'ve solved the JWT challenge!!',
          jwt_token: decoded_token
        }
        res.status(200).json(success);
      }
    });
  }
});

app.post('/jwt/weak-secret', (req, res) => { //weak-secret endpoint
  const { jwt_token } = req.body;

  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {
    const secret_key = 'slipknot666';
    JWT.verify(jwt_token, secret_key, { algorithm: 'HS256', complete: true, audience: 'https://127.0.0.1/jwt/weak-secret' }, (err, decoded_token) => {
      if (err) {
        res.status(400).json(err);
      } else {
        const success = {
          message: 'Congrats!! You\'ve solved the JWT challenge!!',
          jwt_token: decoded_token
        }
        res.status(200).json(success);
      }
    });
  }
});

app.post('/jwt/key-confusion', (req, res) => { //key-confusion endpoint
  const { jwt_token } = req.body;

  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {
    const publicKey = fs.readFileSync(`${__dirname}/certificate/public_key_kca.crt`);
    JWT.verify(jwt_token, publicKey, { algorithms: ['RS256', 'HS256'], complete: true, audience: 'https://127.0.0.1/jwt/key-confusion' }, (err, decoded_token) => {
      if (err) {
        res.status(400).json(err);
      } else {
        const success = {
          message: 'Congrats!! You\'ve solved the JWT challenge!!',
          jwt_token: decoded_token
        }
        res.status(200).json(success);
      }
    });
  }
});

app.post('/jwt/key-injection', (req, res) => { //key-injection endpoint
  const { jwt_token } = req.body;

  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {

    const jwt_b64_dec = JWT.decode(jwt_token, { complete: true });
    thepublicKey = jwkToPem(jwt_b64_dec.header.jwk);

    JWT.verify(jwt_token, thepublicKey, { algorithm: 'RS256', complete: true, audience: 'https://127.0.0.1/jwt/key-injection' }, (err, decoded_token) => {
      if (err) {
        res.status(400).json(err);
      } else {
        const success = {
          message: 'Congrats!! You\'ve solved the JWT challenge!!',
          jwt_token: decoded_token
        }
        res.status(200).json(success);
      }
    });
  }
});

app.post('/jwt/jku', (req, res) => { //jku endpoint
  const { jwt_token } = req.body;
  let thepublicKey = {};
  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {

    const jwt_b64_dec = JWT.decode(jwt_token, { complete: true });
    request(jwt_b64_dec.header.jku, (error, response, body) => {
      if (error) {
        res.status(500).json(error);
      } else {
        if (response.statusCode == 200) {
          thepublicKey = jwkToPem(JSON.parse(body));
          JWT.verify(jwt_token, thepublicKey, { algorithm: 'RS256', complete: true, audience: 'https://127.0.0.1/jwt/jku' }, (err, decoded_token) => {
            if (err) {
              res.status(400).json(err);
            } else {
              const success = {
                message: 'Congrats!! You\'ve solved the JWT challenge!!',
                jwt_token: decoded_token
              }
              res.status(200).json(success);
            }
          });
        }
        else {
          res.status(500).json(`An error has ocurred reaching ${jwt_b64_dec.header.jku}, status: ${response.statusCode}`);
        }
      }
    });
  }
});

app.post('/jwt/x5u', (req, res) => { //x5u endpoint
  const { jwt_token } = req.body;

  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {
    const jwt_b64_dec = JWT.decode(jwt_token, { complete: true });
    request(jwt_b64_dec.header.x5u, (error, response, body) => {
      if (error) {
        res.status(500).send(error);
      } else {
        if (response.statusCode == 200) {
          fs.writeFile(`${__dirname}/certificate/temp_x5u.cert`, body, (err) => {
            if (err) {
              res.status(500).send(err);
            } else {
              exec(` openssl x509 -in ${__dirname}/certificate/temp_x5u.cert -noout -pubkey`, (error, x509cert, stderr) => {
                if (error) {
                  res.status(500).send(error.message);
                }
                if (stderr) {
                  res.status(500).send(stderr);
                }
                JWT.verify(jwt_token, x509cert, { algorithm: 'RS256', complete: true, audience: 'https://127.0.0.1/jwt/x5u' }, (err, decoded_token) => {
                  if (err) {
                    res.status(400).json(err);
                  } else {
                    const success = {
                      message: 'Congrats!! You\'ve solved the JWT challenge!!',
                      jwt_token: decoded_token
                    }
                    res.status(200).json(success);
                  }
                });
              });
            }
          });
        }
        else {
          res.status(500).send(response.body);
        }
      }
    });
  }
});

app.post('/jwt/kid00', (req, res) => { //kid endpoint command execution
  const { jwt_token } = req.body;

  if (jwt_token === null) {
    res.status(400).send('Send a HTTP request with a body with the format: {jwt: "< Place the JWT to test here >"}');
  } else {
    const jwt_b64_dec = JWT.decode(jwt_token, { complete: true });

    if (jwt_b64_dec.header.kid) {
      exec(`cat ${__dirname}/secrets/${jwt_b64_dec.header.kid}`, (error, secret_key, stderr) => {
        if (error) {
          res.status(200).send(error);
        }
        if (stderr) {
          res.status(200).send(stderr);
        }
        JWT.verify(jwt_token, secret_key, { algorithm: 'HS256', complete: true, audience: 'https://127.0.0.1/jwt/kid00' }, (err, decoded_token) => {
          if (err) {
            res.status(400).json(err);
          } else {
            res.status(200).json(decoded_token);
          }
        });
      });
    }
  }
});


app.get('/webkeys/certificate_x509.crt', (req, res) => { //makes the certificate available, this is for xsu attack
  fs.readFile(`${__dirname}/webkeys/certificate_x509.crt`, (err, data) => {
    if (err) {
      res.status(404).json(err);
    }
    else {
      res.status(200).send(data);
    }
  });
});

app.get('/webkeys/jwks.json', (req, res) => { //makes the json web key available, this is for jku attack
  fs.readFile(`${__dirname}/webkeys/jwks.json`, (err, data) => {
    if (err) {
      res.status(404).json(err);
    }
    else {
      res.status(200).json(JSON.parse(data));
    }
  });
});

app.post("/jwt", (req, res) => {
  const { attack } = req.body;
  if (attack === null) {
    res.status(400).send('provided a valid attack value');
  }

  //Generate token to be used in alg:none attack.
  if (attack === 'none') {
    JWT.sign(payload, '885ae2060fbedcfb491c5e8aafc92cab5a8057b3d4c39655acce9d4f09280a20', { algorithm: 'HS256', audience: 'https://127.0.0.1/jwt/none' }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/none'
      };
      res.status(200).json(res_body);
    });
  }

  //Generate token to be used in weak-secret attacks.
  if (attack === 'weak-secret') {
    const secret_key = 'slipknot666';
    JWT.sign(payload, secret_key, { algorithm: 'HS256', audience: 'https://127.0.0.1/jwt/weak-secret' }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/weak-secret'
      }
      res.status(200).json(res_body);
    });
  }

  //Generate token to be used in Key-Confusion attacks.  //Swapping RS for HS
  if (attack === 'key-confusion') {
    const privateKey = fs.readFileSync(`${__dirname}/certificate/private_key_kca.key`);
    JWT.sign(payload, privateKey, { algorithm: 'RS256', audience: 'https://127.0.0.1/jwt/key-confusion' }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/key-confusion'
      }
      res.status(200).json(res_body);
    });
  }

  //Generate token to be used in Key-Injection attacks
  if (attack === 'key-injection') {
    jwk = {
      kty: 'RSA',
      kid: 'key-0',
      use: 'sig',
      e: 'AQAB',
      n: '2_AgfALcXXh5eYJRPOS4szQTATmzpK3Fx0Yny3ktek8XkBwmupxF-y6dWRmtg7L1_Ynjczg218VzcH4CNxhHBcZORh7uunWvZnGI31Tgq0wORMU8srNOwrDRDgfFqtzxfb3YhTchzqX9xpfaU-FCp9iFDge8WNAsDQhRofKV96uJmlyyM7Xo6SMhPv1gjKv6oyTvJ0mBncAJOpqLuV9Vj6Cr42LQd6IjW7se-6xzalkVkj4ZoYJAkBpqueh9ZJV87O2FHRF41Q3wc9yIIcttAAGH_YOgFlMIi3ORDJdqlEGondjwj2q22KcnsGiRRZE98nYVpi4WbvD-4vvpFU_8EhttMz1DQ4IQ6koP8-nzKIlZgddupXgCzk6M9yQZ9dJX1H76P3hnCNcGA2CT3-cjq4jjnh9K8nmLio2bW3-c2EIgrnpLUORy3_F0U5CS22UjCZWmeUkR0J8H3bByOfoP5iw5Bqk6Ovxtt5QWo5jsowNZ9g4TPfi4EBtiLUfWTITv-FWC9i1Jv-sqz6zwM6vthHv47anpp_cBZLk2VCqEF1YQm_Pa_p3_cSDI22KDvrHWZ8xr04srqQWoakicYawcons1GCirilQyjRFsDuGra1l7ad1MkoUKIy2iCzJPpTQ5mem_e654sh4XIrNa99neaClhLoIGLXs5YbWz4eweHQU'
    }
    const privateKey_kia = fs.readFileSync(`${__dirname}/certificate/private_key_kia.key`);
    JWT.sign(payload, privateKey_kia, { algorithm: 'RS256', audience: 'https://127.0.0.1/jwt/key-injection', header: { jwk: jwk } }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/key-injection'
      }
      res.status(200).json(res_body);
    });
  }
  //Generate token to be used in JKU attacks
  if (attack === 'jku') {
    const privateKey_kia = fs.readFileSync(`${__dirname}/certificate/private_key_kia.key`);
    JWT.sign(payload, privateKey_kia, { algorithm: 'RS256', audience: 'https://127.0.0.1/jwt/jku', header: { jku: 'https://127.0.0.1/webkeys/jwks.json' } }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/jku'
      }
      res.status(200).json(res_body);
    });
  }
  //Generate token to be used in X5U attacks
  if (attack === 'x5u') {
    const privateKey_x509 = fs.readFileSync(`${__dirname}/certificate/private_key_x509.key`);
    JWT.sign(payload, privateKey_x509, { algorithm: 'RS256', audience: 'https://127.0.0.1/jwt/x5u', header: { x5u: 'https://127.0.0.1/webkeys/certificate_x509.crt' } }, (err, token) => {
      const res_body = {
        jwt: token,
        endpoint: 'https://127.0.0.1/jwt/x5u'
      }
      res.status(200).json(res_body);
    });
  }
  //Generate token to be used in kid00 (command injection) attack.
  if (attack === 'kid00') {

    exec(`cat ${__dirname}/secrets/keyfile.txt`, (error, secret_key, stderr) => {
      if (error) {
        res.status(200).send(error);
      }
      if (stderr) {
        res.status(200).send(stderr);
      }
      JWT.sign(payload, secret_key, { algorithm: 'HS256', audience: 'https://127.0.0.1/jwt/kid00', header: { kid: 'keyfile.txt' } }, (err, token) => {
        const res_body = {
          jwt: token,
          endpoint: 'https://127.0.0.1/jwt/kid00'
        };
        res.status(200).json(res_body);
      });
    });
  }

});

https.createServer({  //Use a certificate to provide TLS
  key: fs.readFileSync(`${__dirname}/certificate/private_key_kca.key`, (err, data) => {
    console.log(err);
  }),
  cert: fs.readFileSync(`${__dirname}/certificate/certificate_kca.crt`, (err, data) => {
    console.log(err);
  })
}, app).listen(443);