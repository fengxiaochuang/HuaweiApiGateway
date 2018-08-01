const {Signer, HttpRequest} = require("./HuaweiSigner.js")
    , fs = require('fs')
    , https = require("https");

let appKey = "";
let appSecret = "";
var signer = new Signer(appKey, appSecret);

// 假设req是云服务的请求, 实际用的时候替换成自己的req对象.
// 我用的express的req对象, 所以下列数据都是从该对象获取的.
let req;

var request = new HttpRequest();
request.host = req.headers["host"];
request.method = req.method;
request.uri = req.originalUrl;
request.query = req.query;
request.headers = req.headers;
request.body = req.body;

let verify = signer.verify(request);
console.log(verify);