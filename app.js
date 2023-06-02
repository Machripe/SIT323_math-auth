const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken'); //used to generate login tokens
const bcrypt = require('bcrypt'); //used to hash and salt passwords
const express = require('express');
const app = express();
const port = 3000;

// Set private key
const fs = require('fs');
const PRIVATE_KEY = fs.readFileSync('./rsa_private.pem', 'utf8');

const uri = "mongodb://admin:password@mongo-svc:49160";

const client = new MongoClient(uri, {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true
	}
});
const myDB = client.db("user"); // User database 'singular'
const myColl = myDB.collection("users"); // Users database 'plural'

function registerUser(req, res){
	try {
		bcrypt.genSalt(10).then(salt => {
			bcrypt.hash(req.body.password, salt).then(hash => {
				myColl.updateOne({ username: req.body.username }, { $setOnInsert: { username: req.body.username, hash: hash } }, { upsert: true }).then(result => {
					if (result.upsertedId == null) return res.status(401).json({ status: 401, message: "Registration Failure: User already exists" });

					// Token expires in 1 hour
					const expiresIn = '1h';
					const payload = {
						sub: { username: req.body.username }
					};

					const token = jwt.sign(payload, PRIVATE_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });
					res.status(200).json({ status: 200, username: req.body.username, token: token, expiresIn: expiresIn });
				});
			});
		});
	} catch (e) {
		console.log(e.message);
	}
}

function updatePassword(req, res){
	try {
		myColl.findOne({ username: req.body.username }).then(result => {
			if (result == null) return res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });

			bcrypt.compare(req.body.password, result.hash).then(match => {
				if (match) {
					bcrypt.genSalt(10).then(salt => {
						bcrypt.hash(req.body.password, salt).then(hash => {
							myColl.updateOne({ username: req.body.username }, { $set: { username: req.body.username, hash: newHash } }).then(() => {
								res.status(200).json({ status: 200, message: "Password Updated" });
							});
						});
					});
				} else {
					res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });
				}
			});			
		});		
	} catch (e) {
		console.log(e.message);
	}
}

async function deleteUser(req, res){
	try {
		myColl.findOne({ username: req.body.username }).then(result => {
			if (result == null) res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });

			bcrypt.compare(req.body.password, result.hash).then(match => {
				if (match) {
					myColl.deleteOne({ username: req.body.username }).then(result => {
						if (result.deletedCount > 0) return res.status(200).json({ status: 200, message: "Delete successful" });
						res.status(401).json({ status: 401, message: "Delete Failure: User not found" });
					});
				} else {
					res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });
				}
			});
		});		
	} catch (e) {
		console.log(e.message);
	}
}

async function loginUser(req, res){
	try {
		myColl.findOne({ username: req.body.username }).then(result => {
			if (result == null) return res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });
			console.log(result);
			bcrypt.compare(req.body.password, result.hash).then(match => {
				if (match) {
					// Token expires in 1 hour
					const expiresIn = '1h';
					const payload = {
						sub: { username: req.body.username }
					};

					const token = jwt.sign(payload, PRIVATE_KEY, { expiresIn: expiresIn, algorithm: 'RS256' });
					res.status(200).json({ status: 200, username: req.body.username, token: token, expiresIn: expiresIn });
				} else {
					res.status(401).json({ status: 401, message: "Username/Password Incorrect!" });
				}
			});
		});		
	} catch (e) {
		console.log(e.message);
	}
}

async function connectMongoDB(){
	try {
		await client.connect();
		await client.db("admin").command({ ping: 1 });
	}catch(e){
		console.log(e.message);
	}
}
connectMongoDB().catch(console.dir);

app.use(express.json());
app.use((err, req, res, next) => {
    res.status(400).json({ status: 400, message: "Invalid JSON format" })
});

app.post('/register', (req, res) => {
    registerUser(req, res);
});

app.post('/changepass', (req, res) => {
	updatePassword(req, res);
});

app.post('/deleteuser', (req, res) => {
	deleteUser(req, res);
});

app.post('/login', (req, res) => {
    loginUser(req, res);
});

app.use((req, res) => {
    res.sendStatus(404);
});

app.listen(port, () => console.log('listening on port:' + port));