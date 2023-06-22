const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
var db = require('./db');
var AuthController = require('../src/auth/AuthController');
var UserController = require('../src/users/UserController')

// defining the Express app
const app = express();
app.use(express.json())

// adding Helmet to enhance your Rest API's security
app.use(helmet());

// enabling CORS for all requests
app.use(cors());

// adding morgan to log HTTP requests
app.use(morgan('combined'));


app.use('/api/auth', AuthController);
app.use('/api/users', UserController);


module.exports = app;
