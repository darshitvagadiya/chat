var mongoose = require('mongoose');

var userSchema = mongoose.model('User', new mongoose.Schema({
	instagramId : {type: String, index: true},
	email: { type: String, unique: true, lowercase: true },
	password: { type: String, select: false },
	username: String,
	fullName: String,
	picture: String
}));




module.exports = ('User', userSchema);