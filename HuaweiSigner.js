const util = require("util")
    , crypto = require("crypto")
    , moment = require("moment-timezone")
    , BasicDateFormat = "YYYYMMDDTHHmmss[Z]"
    , Algorithm = "SDK-HMAC-SHA256"
    , HeaderXDate = "X-Sdk-Date"
    , HeaderAuthorization = "Authorization"
    , HeaderContentSha256 = "x-sdk-content-sha256";

const noEscape = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0 - 15
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 - 31
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, // 32 - 47
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 48 - 63
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 64 - 79
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 80 - 95
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 96 - 111
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0  // 112 - 127
];

class HttpRequest {
    constructor() {
        this.method = "";
        this.host = "";   //    example.com
        this.uri = "";     //    /request/uri
        this.query = {};
        this.headers = {};
        this.body = "";
    }
}

class Signer {

    constructor(appKey, appSecret) {
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    static hmacsha256(keyByte, message) {
        return crypto.createHmac("SHA256", keyByte).update(message).digest().toString("hex");
    }

    static HexEncodeSHA256Hash(body) {
        return crypto.createHash("SHA256").update(body).digest().toString("hex");
    }

    static urlEncode(str) {
        let hexTable = new Array(256);
        for (var i = 0; i < 256; ++i)
            hexTable[i] = "%" + ((i < 16 ? "0" : "") + i.toString(16)).toUpperCase();

        if (typeof str !== "string") {
            if (typeof str === "object")
                str = String(str);
            else
                str += "";
        }
        let out = "";
        let lastPos = 0;

        for (let i = 0; i < str.length; ++i) {
            let c = str.charCodeAt(i);

            // ASCII
            if (c < 0x80) {
                if (noEscape[c] === 1)
                    continue;
                if (lastPos < i)
                    out += str.slice(lastPos, i);
                lastPos = i + 1;
                out += hexTable[c];
                continue;
            }

            if (lastPos < i)
                out += str.slice(lastPos, i);

            // Multi-byte characters ...
            if (c < 0x800) {
                lastPos = i + 1;
                out += hexTable[0xC0 | (c >> 6)] + hexTable[0x80 | (c & 0x3F)];
                continue;
            }
            if (c < 0xD800 || c >= 0xE000) {
                lastPos = i + 1;
                out += hexTable[0xE0 | (c >> 12)] +
                    hexTable[0x80 | ((c >> 6) & 0x3F)] +
                    hexTable[0x80 | (c & 0x3F)];
                continue;
            }
            // Surrogate pair
            ++i;

            if (i >= str.length)
                throw new errors.URIError("ERR_INVALID_URI");

            var c2 = str.charCodeAt(i) & 0x3FF;

            lastPos = i + 1;
            c = 0x10000 + (((c & 0x3FF) << 10) | c2);
            out += hexTable[0xF0 | (c >> 18)] +
                hexTable[0x80 | ((c >> 12) & 0x3F)] +
                hexTable[0x80 | ((c >> 6) & 0x3F)] +
                hexTable[0x80 | (c & 0x3F)];
        }
        if (lastPos === 0)
            return str;
        if (lastPos < str.length)
            return out + str.slice(lastPos);
        return out;
    }

    static CanonicalRequest(req, signedHeaders) {
        var hexencode;
        if (req.headers[HeaderContentSha256] !== undefined) {
            hexencode = req.headers[HeaderContentSha256];
        } else {
            var data = Signer.RequestPayload(req);
            hexencode = Signer.HexEncodeSHA256Hash(data);
        }
        return req.method + "\n" + Signer.CanonicalURI(req) + "\n" +
            Signer.CanonicalQueryString(req) + "\n" + Signer.CanonicalHeaders(req) + "\n" + signedHeaders + "\n" + hexencode;
    }

    static CanonicalURI(req) {
        var pattens = req.uri.split("/");
        var uri = [];
        for (var k in pattens) {
            var v = pattens[k];
            if (v === "" || v === ".") {

            } else if (v === "..") {
                if (uri.length > 0) {
                    uri.pop();
                }
            } else {
                uri.push(Signer.urlEncode(v));
            }
        }
        var urlpath = "/";
        if (uri.length > 0) {
            urlpath = urlpath + uri.join("/") + "/";
        }
        //req.uri = urlpath
        return urlpath;
    }

    static CanonicalQueryString(req) {
        var a = [];
        for (var key in req.query) {
            var value = req.query[key];
            var kv;
            if (value === "") {
                kv = Signer.urlEncode(key);
            } else {
                kv = Signer.urlEncode(key) + "=" + Signer.urlEncode(value);
            }
            a.push(kv);
        }
        a.sort();
        return a.join("&");
    }

    static CanonicalHeaders(req) {
        var a = [];
        var headers = {};
        for (var key in req.headers) {
            var value = req.headers[key];
            var keyEncoded = key.toLowerCase();
            headers[keyEncoded] = value;
            a.push(keyEncoded + ":" + value.trim());
        }
        a.sort();
        req.headers = headers;
        return a.join("\n") + "\n";
    }

    static SignedHeaders(req) {
        var a = [];
        for (var key in req) {
            a.push(key.toLowerCase());
        }
        a.sort();
        return a.join(";");
    }

    static RequestPayload(req) {
        return req.body;
    }

    static StringToSign(canonicalRequest, time) {
        var bytes = Signer.HexEncodeSHA256Hash(canonicalRequest);
        return Algorithm + "\n" + time.format(BasicDateFormat) + "\n" + bytes;
    }

    static SignStringToSign(stringToSign, signingKey) {
        return Signer.hmacsha256(signingKey, stringToSign);
    }

    static AuthHeaderValue(signature, AppKey, signedHeaders) {
        return Algorithm + " Access=" + AppKey + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
    }

    sign(req, needSignHeader) {
        const headerTime = req.headers[HeaderXDate] || req.headers[HeaderXDate.toLowerCase()];
        let time;
        if (headerTime === undefined) {
            time = moment(Date.now()).tz("utc");
            req.headers[HeaderXDate] = time.format(BasicDateFormat);
        } else {
            time = moment(headerTime, BasicDateFormat);
        }
        if (req.method !== "PUT" && req.method !== "PATCH" && req.method !== "POST") {
            req.body = "";
        }
        let queryString = Signer.CanonicalQueryString(req);
        if (queryString !== "") {
            queryString = "?" + queryString;
        }
        let options = {
            hostname: req.host,
            path: encodeURI(req.uri) + queryString,
            method: req.method,
            headers: req.headers
        };
        Signer.CanonicalHeaders(req);//transfer headers key to lower case
        if (needSignHeader === undefined) {
            needSignHeader = req.headers;
        }

        let signedHeaders = Signer.SignedHeaders(needSignHeader);
        let canonicalRequest = Signer.CanonicalRequest(req, signedHeaders);
        let stringToSign = Signer.StringToSign(canonicalRequest, time);
        let signature = Signer.SignStringToSign(stringToSign, this.appSecret);
        options.headers[HeaderAuthorization] = Signer.AuthHeaderValue(signature, this.appKey, signedHeaders);
        return options;
    }

    verify(request) {
        var req = Object.assign({}, request);
        if (util.isNullOrUndefined(req.headers["authorization"])
        ) {
            return false;
        }
        let authorization = req.headers["authorization"];
        let authorization_field = authorization.replace("SDK-HMAC-SHA256 ", "").replace(/\s/g, "").split(",");
        let authorization_dict = {};
        for (let i = 0; i < authorization_field.length; i++) {
            let ar = authorization_field[i].split("=");
            authorization_dict[ar[0]] = ar[1];
        }
        if (
            util.isNullOrUndefined(authorization_dict["SignedHeaders"]) ||
            util.isNullOrUndefined(authorization_dict["Signature"])) {
            return false;
        }
        let SignedHeaders = authorization_dict["SignedHeaders"];
        let needHeadersString = SignedHeaders.split(";");
        let needSignHeader = {};
        for (let j = 0; j < Object.keys(req.headers).length; j++) {
            let header_key = Object.keys(req.headers)[j];
            let header_value = req.headers[header_key];
            if (needHeadersString.indexOf(header_key.toLowerCase()) > -1) {
                needSignHeader[header_key] = header_value;
            }
        }
        req.headers = needSignHeader;
        let headerTime = req.headers[HeaderXDate] || req.headers[HeaderXDate.toLowerCase()];

        let time;
        if (headerTime === undefined) {
            time = moment(Date.now()).tz("utc");
            req.headers[HeaderXDate] = time.format(BasicDateFormat);
        } else {
            time = moment(headerTime, BasicDateFormat);
        }
        if (req.method !== "PUT" && req.method !== "PATCH" && req.method !== "POST") {
            req.body = "";
        }
        Signer.CanonicalHeaders(req);//transfer headers key to lower case
        let signedHeaders = Signer.SignedHeaders(needSignHeader);
        let canonicalRequest = Signer.CanonicalRequest(req, signedHeaders);
        let stringToSign = Signer.StringToSign(canonicalRequest, time);
        let signature = Signer.SignStringToSign(stringToSign, this.appSecret);
        if (util.isNullOrUndefined(authorization_dict["Signature"])) {
            return false;
        } else {
            return signature === authorization_dict["Signature"];
        }
    }
}

module.exports = {
    Signer, HttpRequest
};
