var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../users/User');

//Get all users
router.get('/', async function (req, res) {
    var users = await User.find({},{password : 0});
    res.send(users);
});

//Get user by id
router.get('/:id', async function (req, res) {
    var user = await User.findOne({ _id: req.body.id }, { password: 0 });
    res.send(user);
});

module.exports = router;