import express from 'express'
import fs from 'fs'
import crypto from 'crypto'
import cors from 'cors'
import cookie_parser from 'cookie-parser'

const app = express.Router()

const algorithm = 'aes256'
const key = Buffer.from(process.env.key, 'hex')
const iv = Buffer.from(process.env.iv, 'hex')

function encrypt(message) {
	let cipher = crypto.createCipheriv(algorithm, key, iv)
	let encryptedMessage = cipher.update(message, 'utf-8', 'hex')
	encryptedMessage += cipher.final('hex')

	return encryptedMessage.toString()
}

function decrypt(message) {
	message = message.toString()
	let decipher = crypto.createDecipheriv(algorithm, key, iv)
	let decryptedMessage = decipher.update(message, 'hex', 'utf-8')
	decryptedMessage += decipher.final('utf-8')

	return decryptedMessage.toString()
}

// fs.writeFileSync("data/websites.json",encrypt(fs.readFileSync("data/websites.json")))

app.post("/verify-website", (req,res)=>{
	const website_data = JSON.parse(decrypt(fs.readFileSync("data/websites.json")))

	if (!req.body["website"] || !req.body["password"]) {
		res.statusCode = 400
		res.write("Missing website or password")
		res.end()
		return
	}

	if (!(req.body["website"] in website_data["websites"])) {
		res.statusCode = 404
		res.write("Website does not exist")
		res.end()
		return
	}

	const hash = crypto.createHash('md5')
	const salt = website_data["websites"][req.body["website"]]["password"]["salt"]
	const hashed_password = website_data["websites"][req.body["website"]]["password"]["hashed-password"]

	if (hash.update(req.body["password"] + salt).digest('hex') == hashed_password) {
		res.statusCode = 200
		res.write("Correct credentials_" + website_data["websites"][req.body["website"]]["tracking-code"])
		res.end()
	} else {
		res.statusCode = 403
		res.write("Incorrect credentials")
		res.end()
	}
})

app.post("/create-website", (req,res)=>{
	const website_data = JSON.parse(decrypt(fs.readFileSync("data/websites.json")))
	
	if (!req.body["website"] || !req.body["password"]) {
		res.statusCode = 400
		res.write("Missing website or password")
		res.end()
		return
	}

	if (website_data["websites"][req.body["website"]]) {
		res.statusCode = 409
		res.write("Website already exists")
		res.end()
		return
	}

	const hash = crypto.createHash('md5')
	const salt = crypto.randomBytes(64).toString("hex")

	const tracking_code = crypto.randomBytes(64).toString("hex")
	
	website_data["websites"][req.body["website"]] = {
		"password": {
			"hashed-password":hash.update(req.body["password"] + salt).digest('hex'),
			"salt": salt,
		},
		"tracking-code": tracking_code
	}
	website_data["tracking-codes"][tracking_code] = req.body["website"]
	fs.writeFileSync("data/websites.json",encrypt(JSON.stringify(website_data, null, 2)))
	fs.writeFileSync("data/analytics/"+tracking_code+".json",encrypt("{}"))

	res.end("Analytics Website Created_" + tracking_code)
})

app.post("/data", (req,res)=>{
	const parsed_url = new URL("https://"+req.hostname+req.url)
	if (!parsed_url.searchParams.get("tracking-code")) {
		res.statusCode = 400
		res.write("No tracking code")
		res.end()
		return
	}
	const website_data = JSON.parse(decrypt(fs.readFileSync("data/websites.json")))
	if (!website_data["tracking-codes"][parsed_url.searchParams.get("tracking-code")]) {
		res.statusCode = 400
		res.write("Tracking code invalid")
		res.end()
		return
	}
	if (!("location" in req.body) || !("time-of-visit" in req.body) || !("ip" in req.body) || !("unique" in req.body)) {
		res.statusCode = 400
		res.write("Malformed data")
		res.end()
		return
	}
	const analytics_data = JSON.parse(decrypt(fs.readFileSync("data/analytics/"+parsed_url.searchParams.get("tracking-code")+".json")))

	if (!analytics_data[req.body["location"]]) {
		analytics_data[req.body["location"]] = {}
	}

	if (!analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)]) {
		analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)] = {
			"unique-visitors": 0,
			"returning-visitors": 0
		}
	}
	
	if (req.body["unique"]) {
		analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)]["unique-visitors"] += 1
	} else {
		analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)]["returning-visitors"] += 1
	}

	if (!analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)]["users"]) {
		analytics_data[req.body["location"]][Math.floor(req.body["time-of-visit"] / 60)]["users"] = []
	}

	const location = req.body["location"]

	delete req.body["location"]

	analytics_data[location][Math.floor(req.body["time-of-visit"] / 60)]["users"].push(req.body)
	
	fs.writeFileSync("data/analytics/"+parsed_url.searchParams.get("tracking-code")+".json",encrypt(JSON.stringify(analytics_data, null, 2)))

	res.end("Data recieved")
})

app.post("/data/get", (req,res)=>{
	const website_data = JSON.parse(decrypt(fs.readFileSync("data/websites.json")))

	const parsed_url = new URL("https://"+req.hostname+req.url)
	if (!parsed_url.searchParams.get("tracking-code")) {
		res.statusCode = 400
		res.write("No tracking code")
		res.end()
		return
	}
	if (!website_data["tracking-codes"][parsed_url.searchParams.get("tracking-code")]) {
		res.statusCode = 400
		res.write("Tracking code invalid")
		res.end()
		return
	}

	if (!req.body["website"] || !req.body["password"]) {
		res.statusCode = 400
		res.write("Missing website or password")
		res.end()
		return
	}

	if (!(req.body["website"] in website_data["websites"])) {
		res.statusCode = 404
		res.write("Website does not exist")
		res.end()
		return
	}

	const hash = crypto.createHash('md5')
	const salt = website_data["websites"][req.body["website"]]["password"]["salt"]
	const hashed_password = website_data["websites"][req.body["website"]]["password"]["hashed-password"]

	if (hash.update(req.body["password"] + salt).digest('hex') == hashed_password) {
		const analytics_data = decrypt(fs.readFileSync("data/analytics/" + parsed_url.searchParams.get("tracking-code") + ".json"))
		res.write(analytics_data)
		res.end()
	} else {
		res.statusCode = 403
		res.write("Incorrect credentials")
		res.end()
	}
})

export default app
