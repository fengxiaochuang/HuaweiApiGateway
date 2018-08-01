# HuaweiApiGateway

华为网关签名和验证SDK node版本
> 根据官方提供的ApiGateway-javascript-sdk-1.0.1修改的:

    1. x-sdk-date不区分大小写
    2. 不自动拼host进入校验
    3. 根据官方接口返回的SignedHeaders自动选择验证签名字段

依赖 moment-timezone

提供两个主要接口: sign 和 verify

## sign 接口
```js
const {Signer, HttpRequest} = require("./HuaweiSigner.js")

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
request.body = new Buffer(fs.readFileSync("./audio.pcm"));

// 签名并返回http options
let opt = signer.sign(request);
```

## verify 接口
```js
const {Signer, HttpRequest} = require("./HuaweiSigner.js")

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

// 返回true或者false
let verify = signer.verify(request);

```

具体使用请参考sign_test和verify_test进行调试.