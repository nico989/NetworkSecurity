var fs = require('fs');
const http = require('http');
const https = require('https');
const privateKey  = fs.readFileSync('certs/server/server.key', 'utf8');
const certificate = fs.readFileSync('certs/server/server.crt', 'utf8');
const ca = fs.readFileSync('certs/ca/ca.crt', 'utf8');

const options = {
    key: privateKey, 
    cert: certificate,
    ca: ca,
    requestCert: true,
    rejectUnauthorized: true,
    };
const auth = {username: 'admin', password: 'admin'};
const express = require('express');
const bodyParser = require('body-parser'); 
const request = require('request');
const { response } = require('express');
const app = express();
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

app.get('/', (_, res) => res.sendFile(__dirname + '/index.html'));

app.post('/login', function (req, res) {  
    var response = {  
        status: 200,
        message: 'Login ok'
    };

    if (!req.body.captcha){
      response.status = 402;
      response.message = 'Please select captcha';
    }

    if (req.body.username != auth.username || req.body.password != auth.password) {
      response.status = 401;
      response.message = 'Login failed';
    }

    const secretKey = "6LdpFnEaAAAAAHI4ye0G5k5bh77rmGYNMaInYSpM";
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${req.body.captcha}&remoteip=${req.connection.remoteAddress}`;
    request(verificationUrl,function(err,resp,body) {
        body = JSON.parse(body);
        if(body.success !== undefined && !body.success) {
          response.status = 401;
          response.message = 'Login failed';
        }
    });

    res.end(JSON.stringify(response));  
 })  


var httpServer = http.createServer(app);
var httpsServer = https.createServer(options, app);

httpServer.listen(4080, () => {
    console.log(`Example app listening at http://localhost:4080`)
})
httpsServer.listen(4443, () => {
    console.log(`Example app listening at https://localhost:4443`)
})
