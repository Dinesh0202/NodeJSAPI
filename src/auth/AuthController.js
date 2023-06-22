const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
const User = require('../users/User');
const { check, validationResult } = require('express-validator');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const VerifyToken = require('./VerifyToken');
const randToken = require('rand-token');

var refreshTokens = {};

router.post('/register',[check('username').isLength({ min: 5 }).withMessage('userName Must be more than 5 charterers'),check('email').isEmail().withMessage("Use Correct Email"),check('password').isStrongPassword( {minLength: 8, minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1}).withMessage("Password must include one lowercase character, one uppercase character, a number, and a special character.")], async function (req, res) {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() })
    }
    var hashedPassword = await bcrypt.hashSync(req.body.password, 10);

    await User.create({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword
    },
        async function (err, user) {
            if (err) return res.status(500).send("Something went wrong.");
            //create a token
            var token = jwt.sign({ id: user._id }, config.secret, {
                expiresIn: 300
            });

            var refreshToken = randToken.uid(256);
            refreshTokens[refreshToken] = req.body.email;
            res.status(200).send({ userId: user._id, auth: true, token: token, refreshToken: refreshToken });
        });
});

router.get('/me', VerifyToken, async function (req, res) {
   
        //res.status(200).send(decoded);
        User.findById(req.userId, {password:0}, async function (err, user) {
            if (err) return res.status(500).send("Something went wrong.");

            if (!user) return res.status(404).send("No user found.");

            res.status(200).send(user);
        })
});

router.post('/login', async function (req, res) {
   await User.findOne({ email: req.body.email }, async function (err, user) {
        if (err) return res.status(500).send('Something went wrong.');

        if (!user) return res.status(404).send("User not found.");

        var passwordIsValid = await bcrypt.compare(req.body.password, user.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 300 
        });
       var refreshToken = randToken.uid(256);
       refreshTokens[refreshToken] = user._id;
        res.status(200).send({ userId : user._id, auth: true, token: token, refreshToken : refreshToken });
    }).clone();
});

router.post('/token', async function (req, res) {
    var userId = req.body.userId;
    var refreshToken = req.body.refreshToken;
    if ((refreshToken in refreshTokens) && (refreshTokens[refreshToken] == userId)) {
        var token = jwt.sign({ id: userId }, config.secret, {
            expiresIn: 300
        });
        var refreshToken = randToken.uid(256);
        refreshTokens[refreshToken] = userId;
        res.status(200).send({ auth: true, token: token, refreshToken: refreshToken });
    }
    else {
        res.status(401).send("Unauthorized.");
    }
})


module.exports = router;