const {Signer, HttpRequest} = require("./HuaweiSigner.js")
    , fs = require('fs')
    , https = require("https");

// 初始化
let AppKey = "";
let AppSecret = "";
var signer = new Signer(AppKey, AppSecret);

// 构造request
let request = new HttpRequest();
request.host = "";
request.method = "";
request.uri = "";
request.headers = {};
request.query = "";
request.body = new Buffer(fs.readFileSync("./kendeji.pcm"));

let opt = signer.sign(request);
console.log(opt.headers);
const req = https.request(opt, function (res) {
    res.on("data", function (chunk) {
        console.log(chunk.toString())
    })
});

req.on("error", function (err) {
    console.log(err.message)
});
req.write(request.body);
req.end();
