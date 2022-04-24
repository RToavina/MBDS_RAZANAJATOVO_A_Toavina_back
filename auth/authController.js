// AuthController.js

let express = require('express');
let router = express.Router();
let bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
let User = require('../model/User');

let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let config = require('../config');
let VerifyToken = require('./VerifyToken');


router.post('/register', userAlreadyExist, function(req, res) {

    let hashedPassword = bcrypt.hashSync(req.body.password, 8);

    User.create({
            name : req.body.name,
            email : req.body.email,
            password : hashedPassword,
            isAdmin : req.body.isAdmin
        },
        function (err, user) {
            if (err) return res.status(500).send("There was a problem registering the user.")
            // create a token
            let token = jwt.sign({ id: user._id }, config.secret, {
                expiresIn: 86400 // expires in 24 hours
            });
            // set it in an HTTP Only + Secure Cookie
            res.cookie("SESSIONID", token, {httpOnly:true, secure:true});
            res.status(200).send({ auth: true, token: token });
        });
});

router.get('/me', VerifyToken, function(req, res, next) {

    User.findById(req.userId, { password: 0 }, function (err, user) {
        if (err) return res.status(500).send("There was a problem finding the user.");
        if (!user) return res.status(404).send("No user found.");

        res.status(200).send(user);
    });
});


router.post('/login', function(req, res) {

    User.findOne({ email: req.body.email }, function (err, user) {
        if (err) return res.status(500).send('Error on the server.');
        if (!user) return res.status(404).send('No user found.');

        let passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        let token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // expires in 24 hours
        });
        res.cookie("SESSIONID", token, {httpOnly:true, secure:true});
        res.status(200).send({ auth: true, token: token });
    });

});

router.get('/logout', function(req, res) {
    res.status(200).send({ auth: false, token: null });
});

function userAlreadyExist(req, res, next) {
    User.findOne({ email: req.body.email }, function (err, user) {
        if (err) return res.status(500).send('Error on the server.');
        if (user) return res.status(404).send('User already found.');
        next();
    });
}

module.exports = router;