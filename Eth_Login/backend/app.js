const express = require('express');
const bodyParser = require('body-parser');
const LoginContract = require('./login_contract.js');
const jwt = require('jsonwebtoken');
const cuid = require('cuid');
const cors = require('cors');

// LoginAttempt is the name of the event that signals logins in the 
// Login contract. This is specified in the login.sol file.

const challenges = {};
const successfulLogins = {};

const events = LoginContract.events.LoginAttempt();

events._emitter.on("connected", function(subscriptionId){
    console.log(subscriptionId);
})
.on('data', function(event){
    console.log(event); // same results as the optional callback above
    // If the challenge sent through Ethereum matches the one we generated,
    // mark the login attempt as valid, otherwise ignore it.
    const { sender, challenge } = event.returnValues;
    console.log(challenges);

    console.log('Sender:', sender);
    console.log('Challenge:', challenge);
    if(challenges[sender.toLowerCase()] === challenge) {
        successfulLogins[sender.toLowerCase()] = true;
    }
})
.on('error', function(error, receipt) { // If the transaction was rejected by the network with a receipt, the second parameter will be the receipt.
    console.log(error);
});


// LoginContract.getPastEvents("LoginAttempt", { fromBlock: 0, toBlock: 'latest' }, (error, event) => {
//     if(error) {
//         console.log(error);
//         return;
//     }
//     console.log("here-past");
//     console.log(event);
// }).then(events => {
//     console.log(challenges); // same results as the optional callback above
//     console.log(successfulLogins);
//     console.log(events[0].returnValues.sender + events[0].returnValues.challenge);
// })
// .catch(error => {
//     console.error(error);
// });




// From here on its just express.js
const secret = process.env.JWT_SECRET || "my super secret passcode";

const app = express();
// WARNING: CHANGE IN PRODUCTION
app.use(cors({
    origin: 'http://localhost:8080'
}))
app.use(bodyParser.json({ type: () => true }));

function validateJwt(req, res, next) {
    try {
        req.jwt = jwt.verify(req.body.jwt, secret, { 
            algorithms: ['HS256'] 
        });
        next();
    } catch(e) {
        res.sendStatus(401); //Unauthorized
    }
}

app.post('/login', (req, res) => {
    // All Ethereum addresses are 42 characters long
    if(!req.body.address || req.body.address.length !== 42) {
        res.sendStatus(400);
        return;
    }

    req.body.address = req.body.address.toLowerCase();

    const challenge = cuid();
    challenges[req.body.address] = challenge;

    const token = jwt.sign({ 
        address: req.body.address, 
        access: 'finishLogin'
    }, secret);

    res.json({
        challenge: challenge,
        jwt: token
    });
});

app.post('/finishLogin', validateJwt, (req, res) => {
    if(!req.jwt || !req.jwt.address || req.jwt.access !== 'finishLogin') {
        res.sendStatus(400);
        return;
    }

    if(successfulLogins[req.jwt.address]) {
        delete successfulLogins[req.jwt.address];
        delete challenges[req.jwt.address];

        const token = jwt.sign({ 
            address: req.jwt.address, 
            access: 'full'
        }, secret);

        res.json({
            jwt: token,
            address: req.jwt.address
        });
    } else {
        // HTTP Accepted (not completed)
        res.sendStatus(202);
    }
});

app.post('/apiTest', validateJwt, (req, res) => {
    if(req.jwt.access !== 'full') {
        res.sendStatus(401); //Unauthorized
        return;
    }

    res.json({
        message: 'It works!'
    });
});

app.listen(process.env.PORT || 3000);