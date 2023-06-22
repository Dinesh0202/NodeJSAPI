const mongoose = require("mongoose");

const schema = mongoose.Schema({
    username: String,
    email: {type:String,require:true}, 
    password: {type:String,require:true}

});

module.exports = mongoose.model("User", schema);