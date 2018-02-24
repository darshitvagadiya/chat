"use strict"
var Conversation = require('../models/conversation');
var Message = require('../models/message');
var User = require('../models/user');

exports.getConversations = function(req, res, next){
	Conversation.find({ participants: req.user._id })
		.select('_id')
		.exec(function(err, conversations){
			if(err){
				res.send({ error: err });
				return next(err);
			}

			let fullConversations = [];
			conversations.forEach(function(conversation){
				Message.find({ 'conversationId': conversation._id })
					.sort('-createdAt')
					.limit(1)
					.populate({
						path: "author",
						select: "fullName"
					})
					.exec(function(err, message){
						if(err){
							res.send({ error: err });
							return next(err);
						}
						fullConversations.push(message);
						if(fullConversations.length === conversations.length){
							return res.status(200).json({ conversations: fullConversations });
						}
					});
			});
		});
};

exports.getConversation = function(req, res, next){
	Message.find({ conversationId: req.params.conversationId })
		.select('createdAt body author')
		.sort('-createdAt')
		.populate({
			path: 'author',
			select: 'fullName'
		})
		.exec(function(err, messages){
			if(err){
				res.send({ error: err });
				return next(err);
			}
			res.status(200).json({ conversation: messages });
		});
};

exports.newConversation = function(req, res, next){
	if(!req.params.recipient){
		res.status(422).send({ error: 'Please choose a valid recipient for your message.' });
		return next();
	}

	if(!req.body.composedMessage){
		res.status(422).send({ error: 'Please enter a message.' });
	}

	var conversation = new Conversation({
		participants: [req.user._id, req.params.recipient]
	});

	conversation.save(function(err, newConversation){
		if(err){
			res.send({ error: err });
			return next(err);
		}
		var message = new Message({
			conversationId: newConversation._id,
			body: req.body.composedMessage,
			author: req.user._id
		});

		message.save(function(err, newMessage){
			if(err){
				res.send({ error: err });
				return next(err);
			}
			res.status(200).json({ message: 'Conversation Started!', conversationId: conversation._id });
			return next();
		});
	});
};

exports.sendReply = function(req, res, next){
	var reply = new Message({
		conversationId: req.params.conversationId,
		body: req.body.composedMessage,
		author: req.user._id
	});

	reply.save(function(err, sentReply){
		if(err){
			res.send({ error: err });
			return next(err);
		}
		res.status(200).json({ message: 'Reply successfully sent.' });
		return(next);
	});
};