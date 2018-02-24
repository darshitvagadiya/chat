var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var MessageSchema = new Schema({
	conversationId: {
		type: Schema.Types.ObjectId,
		require: true
	},
	body: {
		type: String,
		required: true
	},
	author: {
		type: Schema.Types.ObjectId,
		ref: 'User'
	}
},
{
	timestamps: true
});

module.exports = mongoose.model('Message', MessageSchema);