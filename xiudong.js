//md5算法
var HEX_CHARS = "0123456789abcdef".split(""), EXTRA = [128, 32768, 8388608, -2147483648], SHIFT = [0, 8, 16, 24],
    OUTPUT_TYPES = ["hex", "array", "digest", "buffer", "arrayBuffer", "base64"],
    BASE64_ENCODE_CHAR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(""), blocks = [],
    buffer8;
var ARRAY_BUFFER = true;

var buffer = new ArrayBuffer(68);
buffer8 = new Uint8Array(buffer),
    blocks = new Uint32Array(buffer)

function Md5(e) {
    if (e)
        blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0,
            this.blocks = blocks,
            this.buffer8 = buffer8;
    else if (ARRAY_BUFFER) {
        var n = new ArrayBuffer(68);
        this.buffer8 = new Uint8Array(n),
            this.blocks = new Uint32Array(n)
    } else
        this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    this.h0 = this.h1 = this.h2 = this.h3 = this.start = this.bytes = this.hBytes = 0,
        this.finalized = this.hashed = !1,
        this.first = !0
}

Md5.prototype.update = function (e) {
    if (!this.finalized) {
        var n,
            t = 'string';
        if ("string" !== t) {
            if ("object" !== t)
                throw ERROR;
            if (null === e)
                throw ERROR;
            if (ARRAY_BUFFER && e.constructor === ArrayBuffer)
                e = new Uint8Array(e);
            else if (!Array.isArray(e) && (!ARRAY_BUFFER || !ArrayBuffer.isView(e)))
                throw ERROR;
            n = !0
        }
        var a,
            i,
            o = 0,
            r = e.length,
            s = this.blocks,
            c = this.buffer8;
        while (o < r) {
            if (this.hashed && (this.hashed = !1,
                s[0] = s[16],
                s[16] = s[1] = s[2] = s[3] = s[4] = s[5] = s[6] = s[7] = s[8] = s[9] = s[10] = s[11] = s[12] = s[13] = s[14] = s[15] = 0),
                n)
                if (ARRAY_BUFFER)
                    for (i = this.start; o < r && i < 64; ++o)
                        c[i++] = e[o];
                else
                    for (i = this.start; o < r && i < 64; ++o)
                        s[i >> 2] |= e[o] << SHIFT[3 & i++];
            else if (ARRAY_BUFFER)
                for (i = this.start; o < r && i < 64; ++o)
                    a = e.charCodeAt(o),
                        a < 128 ? c[i++] = a : a < 2048 ? (c[i++] = 192 | a >> 6,
                            c[i++] = 128 | 63 & a) : a < 55296 || a >= 57344 ? (c[i++] = 224 | a >> 12,
                            c[i++] = 128 | a >> 6 & 63,
                            c[i++] = 128 | 63 & a) : (a = 65536 + ((1023 & a) << 10 | 1023 & e.charCodeAt(++o)),
                            c[i++] = 240 | a >> 18,
                            c[i++] = 128 | a >> 12 & 63,
                            c[i++] = 128 | a >> 6 & 63,
                            c[i++] = 128 | 63 & a);
            else
                for (i = this.start; o < r && i < 64; ++o)
                    a = e.charCodeAt(o),
                        a < 128 ? s[i >> 2] |= a << SHIFT[3 & i++] : a < 2048 ? (s[i >> 2] |= (192 | a >> 6) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | 63 & a) << SHIFT[3 & i++]) : a < 55296 || a >= 57344 ? (s[i >> 2] |= (224 | a >> 12) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | a >> 6 & 63) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | 63 & a) << SHIFT[3 & i++]) : (a = 65536 + ((1023 & a) << 10 | 1023 & e.charCodeAt(++o)),
                            s[i >> 2] |= (240 | a >> 18) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | a >> 12 & 63) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | a >> 6 & 63) << SHIFT[3 & i++],
                            s[i >> 2] |= (128 | 63 & a) << SHIFT[3 & i++]);
            this.lastByteIndex = i,
                this.bytes += i - this.start,
                i >= 64 ? (this.start = i - 64,
                    this.hash(),
                    this.hashed = !0) : this.start = i
        }
        return this.bytes > 4294967295 && (this.hBytes += this.bytes / 4294967296 << 0,
            this.bytes = this.bytes % 4294967296),
            this
    }
},
    Md5.prototype.finalize = function () {
        if (!this.finalized) {
            this.finalized = !0;
            var e = this.blocks,
                n = this.lastByteIndex;
            e[n >> 2] |= EXTRA[3 & n],
            n >= 56 && (this.hashed || this.hash(),
                e[0] = e[16],
                e[16] = e[1] = e[2] = e[3] = e[4] = e[5] = e[6] = e[7] = e[8] = e[9] = e[10] = e[11] = e[12] = e[13] = e[14] = e[15] = 0),
                e[14] = this.bytes << 3,
                e[15] = this.hBytes << 3 | this.bytes >>> 29,
                this.hash()
        }
    },
    Md5.prototype.hash = function () {
        var e,
            n,
            t,
            a,
            i,
            o,
            r = this.blocks;
        this.first ? (e = r[0] - 680876937,
            e = (e << 7 | e >>> 25) - 271733879 << 0,
            a = (-1732584194 ^ 2004318071 & e) + r[1] - 117830708,
            a = (a << 12 | a >>> 20) + e << 0,
            t = (-271733879 ^ a & (-271733879 ^ e)) + r[2] - 1126478375,
            t = (t << 17 | t >>> 15) + a << 0,
            n = (e ^ t & (a ^ e)) + r[3] - 1316259209,
            n = (n << 22 | n >>> 10) + t << 0) : (e = this.h0,
            n = this.h1,
            t = this.h2,
            a = this.h3,
            e += (a ^ n & (t ^ a)) + r[0] - 680876936,
            e = (e << 7 | e >>> 25) + n << 0,
            a += (t ^ e & (n ^ t)) + r[1] - 389564586,
            a = (a << 12 | a >>> 20) + e << 0,
            t += (n ^ a & (e ^ n)) + r[2] + 606105819,
            t = (t << 17 | t >>> 15) + a << 0,
            n += (e ^ t & (a ^ e)) + r[3] - 1044525330,
            n = (n << 22 | n >>> 10) + t << 0),
            e += (a ^ n & (t ^ a)) + r[4] - 176418897,
            e = (e << 7 | e >>> 25) + n << 0,
            a += (t ^ e & (n ^ t)) + r[5] + 1200080426,
            a = (a << 12 | a >>> 20) + e << 0,
            t += (n ^ a & (e ^ n)) + r[6] - 1473231341,
            t = (t << 17 | t >>> 15) + a << 0,
            n += (e ^ t & (a ^ e)) + r[7] - 45705983,
            n = (n << 22 | n >>> 10) + t << 0,
            e += (a ^ n & (t ^ a)) + r[8] + 1770035416,
            e = (e << 7 | e >>> 25) + n << 0,
            a += (t ^ e & (n ^ t)) + r[9] - 1958414417,
            a = (a << 12 | a >>> 20) + e << 0,
            t += (n ^ a & (e ^ n)) + r[10] - 42063,
            t = (t << 17 | t >>> 15) + a << 0,
            n += (e ^ t & (a ^ e)) + r[11] - 1990404162,
            n = (n << 22 | n >>> 10) + t << 0,
            e += (a ^ n & (t ^ a)) + r[12] + 1804603682,
            e = (e << 7 | e >>> 25) + n << 0,
            a += (t ^ e & (n ^ t)) + r[13] - 40341101,
            a = (a << 12 | a >>> 20) + e << 0,
            t += (n ^ a & (e ^ n)) + r[14] - 1502002290,
            t = (t << 17 | t >>> 15) + a << 0,
            n += (e ^ t & (a ^ e)) + r[15] + 1236535329,
            n = (n << 22 | n >>> 10) + t << 0,
            e += (t ^ a & (n ^ t)) + r[1] - 165796510,
            e = (e << 5 | e >>> 27) + n << 0,
            a += (n ^ t & (e ^ n)) + r[6] - 1069501632,
            a = (a << 9 | a >>> 23) + e << 0,
            t += (e ^ n & (a ^ e)) + r[11] + 643717713,
            t = (t << 14 | t >>> 18) + a << 0,
            n += (a ^ e & (t ^ a)) + r[0] - 373897302,
            n = (n << 20 | n >>> 12) + t << 0,
            e += (t ^ a & (n ^ t)) + r[5] - 701558691,
            e = (e << 5 | e >>> 27) + n << 0,
            a += (n ^ t & (e ^ n)) + r[10] + 38016083,
            a = (a << 9 | a >>> 23) + e << 0,
            t += (e ^ n & (a ^ e)) + r[15] - 660478335,
            t = (t << 14 | t >>> 18) + a << 0,
            n += (a ^ e & (t ^ a)) + r[4] - 405537848,
            n = (n << 20 | n >>> 12) + t << 0,
            e += (t ^ a & (n ^ t)) + r[9] + 568446438,
            e = (e << 5 | e >>> 27) + n << 0,
            a += (n ^ t & (e ^ n)) + r[14] - 1019803690,
            a = (a << 9 | a >>> 23) + e << 0,
            t += (e ^ n & (a ^ e)) + r[3] - 187363961,
            t = (t << 14 | t >>> 18) + a << 0,
            n += (a ^ e & (t ^ a)) + r[8] + 1163531501,
            n = (n << 20 | n >>> 12) + t << 0,
            e += (t ^ a & (n ^ t)) + r[13] - 1444681467,
            e = (e << 5 | e >>> 27) + n << 0,
            a += (n ^ t & (e ^ n)) + r[2] - 51403784,
            a = (a << 9 | a >>> 23) + e << 0,
            t += (e ^ n & (a ^ e)) + r[7] + 1735328473,
            t = (t << 14 | t >>> 18) + a << 0,
            n += (a ^ e & (t ^ a)) + r[12] - 1926607734,
            n = (n << 20 | n >>> 12) + t << 0,
            i = n ^ t,
            e += (i ^ a) + r[5] - 378558,
            e = (e << 4 | e >>> 28) + n << 0,
            a += (i ^ e) + r[8] - 2022574463,
            a = (a << 11 | a >>> 21) + e << 0,
            o = a ^ e,
            t += (o ^ n) + r[11] + 1839030562,
            t = (t << 16 | t >>> 16) + a << 0,
            n += (o ^ t) + r[14] - 35309556,
            n = (n << 23 | n >>> 9) + t << 0,
            i = n ^ t,
            e += (i ^ a) + r[1] - 1530992060,
            e = (e << 4 | e >>> 28) + n << 0,
            a += (i ^ e) + r[4] + 1272893353,
            a = (a << 11 | a >>> 21) + e << 0,
            o = a ^ e,
            t += (o ^ n) + r[7] - 155497632,
            t = (t << 16 | t >>> 16) + a << 0,
            n += (o ^ t) + r[10] - 1094730640,
            n = (n << 23 | n >>> 9) + t << 0,
            i = n ^ t,
            e += (i ^ a) + r[13] + 681279174,
            e = (e << 4 | e >>> 28) + n << 0,
            a += (i ^ e) + r[0] - 358537222,
            a = (a << 11 | a >>> 21) + e << 0,
            o = a ^ e,
            t += (o ^ n) + r[3] - 722521979,
            t = (t << 16 | t >>> 16) + a << 0,
            n += (o ^ t) + r[6] + 76029189,
            n = (n << 23 | n >>> 9) + t << 0,
            i = n ^ t,
            e += (i ^ a) + r[9] - 640364487,
            e = (e << 4 | e >>> 28) + n << 0,
            a += (i ^ e) + r[12] - 421815835,
            a = (a << 11 | a >>> 21) + e << 0,
            o = a ^ e,
            t += (o ^ n) + r[15] + 530742520,
            t = (t << 16 | t >>> 16) + a << 0,
            n += (o ^ t) + r[2] - 995338651,
            n = (n << 23 | n >>> 9) + t << 0,
            e += (t ^ (n | ~a)) + r[0] - 198630844,
            e = (e << 6 | e >>> 26) + n << 0,
            a += (n ^ (e | ~t)) + r[7] + 1126891415,
            a = (a << 10 | a >>> 22) + e << 0,
        t += (e ^ (a | ~n)) + r[14] - 1416354905,
        t = (t << 15 | t >>> 17) + a << 0,
        n += (a ^ (t | ~e)) + r[5] - 57434055,
        n = (n << 21 | n >>> 11) + t << 0,
        e += (t ^ (n | ~a)) + r[12] + 1700485571,
        e = (e << 6 | e >>> 26) + n << 0,
        a += (n ^ (e | ~t)) + r[3] - 1894986606,
        a = (a << 10 | a >>> 22) + e << 0,
        t += (e ^ (a | ~n)) + r[10] - 1051523,
        t = (t << 15 | t >>> 17) + a << 0,
        n += (a ^ (t | ~e)) + r[1] - 2054922799,
        n = (n << 21 | n >>> 11) + t << 0,
        e += (t ^ (n | ~a)) + r[8] + 1873313359,
        e = (e << 6 | e >>> 26) + n << 0,
        a += (n ^ (e | ~t)) + r[15] - 30611744,
        a = (a << 10 | a >>> 22) + e << 0,
        t += (e ^ (a | ~n)) + r[6] - 1560198380,
        t = (t << 15 | t >>> 17) + a << 0,
        n += (a ^ (t | ~e)) + r[13] + 1309151649,
        n = (n << 21 | n >>> 11) + t << 0,
        e += (t ^ (n | ~a)) + r[4] - 145523070,
        e = (e << 6 | e >>> 26) + n << 0,
        a += (n ^ (e | ~t)) + r[11] - 1120210379,
        a = (a << 10 | a >>> 22) + e << 0,
        t += (e ^ (a | ~n)) + r[2] + 718787259,
        t = (t << 15 | t >>> 17) + a << 0,
        n += (a ^ (t | ~e)) + r[9] - 343485551,
        n = (n << 21 | n >>> 11) + t << 0,
        this.first ? (this.h0 = e + 1732584193 << 0,
            this.h1 = n - 271733879 << 0,
            this.h2 = t - 1732584194 << 0,
            this.h3 = a + 271733878 << 0,
            this.first = !1) : (this.h0 = this.h0 + e << 0,
            this.h1 = this.h1 + n << 0,
            this.h2 = this.h2 + t << 0,
            this.h3 = this.h3 + a << 0)
    },
    Md5.prototype.hex = function () {
        this.finalize();
        var e = this.h0,
            n = this.h1,
            t = this.h2,
            a = this.h3;
        return HEX_CHARS[e >> 4 & 15] + HEX_CHARS[15 & e] + HEX_CHARS[e >> 12 & 15] + HEX_CHARS[e >> 8 & 15] + HEX_CHARS[e >> 20 & 15] + HEX_CHARS[e >> 16 & 15] + HEX_CHARS[e >> 28 & 15] + HEX_CHARS[e >> 24 & 15] + HEX_CHARS[n >> 4 & 15] + HEX_CHARS[15 & n] + HEX_CHARS[n >> 12 & 15] + HEX_CHARS[n >> 8 & 15] + HEX_CHARS[n >> 20 & 15] + HEX_CHARS[n >> 16 & 15] + HEX_CHARS[n >> 28 & 15] + HEX_CHARS[n >> 24 & 15] + HEX_CHARS[t >> 4 & 15] + HEX_CHARS[15 & t] + HEX_CHARS[t >> 12 & 15] + HEX_CHARS[t >> 8 & 15] + HEX_CHARS[t >> 20 & 15] + HEX_CHARS[t >> 16 & 15] + HEX_CHARS[t >> 28 & 15] + HEX_CHARS[t >> 24 & 15] + HEX_CHARS[a >> 4 & 15] + HEX_CHARS[15 & a] + HEX_CHARS[a >> 12 & 15] + HEX_CHARS[a >> 8 & 15] + HEX_CHARS[a >> 20 & 15] + HEX_CHARS[a >> 16 & 15] + HEX_CHARS[a >> 28 & 15] + HEX_CHARS[a >> 24 & 15]
    },
    Md5.prototype.toString = Md5.prototype.hex,
    Md5.prototype.digest = function () {
        this.finalize();
        var e = this.h0,
            n = this.h1,
            t = this.h2,
            a = this.h3;
        return [255 & e, e >> 8 & 255, e >> 16 & 255, e >> 24 & 255, 255 & n, n >> 8 & 255, n >> 16 & 255, n >> 24 & 255, 255 & t, t >> 8 & 255, t >> 16 & 255, t >> 24 & 255, 255 & a, a >> 8 & 255, a >> 16 & 255, a >> 24 & 255]
    },
    Md5.prototype.array = Md5.prototype.digest,
    Md5.prototype.arrayBuffer = function () {
        this.finalize();
        var e = new ArrayBuffer(16),
            n = new Uint32Array(e);
        return n[0] = this.h0,
            n[1] = this.h1,
            n[2] = this.h2,
            n[3] = this.h3,
            e
    },
    Md5.prototype.buffer = Md5.prototype.arrayBuffer,
    Md5.prototype.base64 = function () {
        for (var e, n, t, a = "", i = this.array(), o = 0; o < 15;)
            e = i[o++],
                n = i[o++],
                t = i[o++],
                a += BASE64_ENCODE_CHAR[e >>> 2] + BASE64_ENCODE_CHAR[63 & (e << 4 | n >>> 4)] + BASE64_ENCODE_CHAR[63 & (n << 2 | t >>> 6)] + BASE64_ENCODE_CHAR[63 & t];
        return e = i[o],
            a += BASE64_ENCODE_CHAR[e >>> 2] + BASE64_ENCODE_CHAR[e << 4 & 63] + "==",
            a
    };

function _md5(data) {
    const hash = new Md5(!0);
    hash.update(data);
    return hash.hex();
}

var base_ = function (e) {
    for (var n = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + (new Date).getTime(), t = e || 20, a = [], i = 0; i < t; i++)
        a.push(n.charAt(Math.floor(Math.random() * n.length)));
    return a.join("")
}
function create_st_flpv(){
    return base_();
}
function create_crtraceid(){
    return base_(32) + (new Date).getTime();
}
function create_crpsign(t_,st_flpv,cuuserref,crtraceid,url_path,I_,sign='',userid='',id_token='') {
    var url = url_path // url路径
    var t = t_ // 只在请求"/waf/gettoken"时的首次为空
        , a = sign
        , i = id_token
        , s = userid
        , y = cuuserref // 同请求头中的cuuserref与cdeviceno(猜测只与当前设备有关,一般不变)
        , I = I_ //'{"st_flpv":"' + st_flpv + '","sign":"","trackPath":""}'
        , f = "wap"
        , h = crtraceid;
    // 其有许多信息与请求头当中的相同
    var E = t + a + i + s + "wap" + y + I + url + "997" + f + h;
    return _md5(E)
}

// AES加密解密
const CryptoJS = require("crypto-js");
const encrypt = function (e, n) {
    n = n || "0RGF99CtUajPF0Ny";
    const t = CryptoJS.enc.Base64,
    a = CryptoJS.enc.Utf8.parse(n),
    r = CryptoJS.enc.Utf8.parse(e),
    s = CryptoJS.AES.encrypt(r, a, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return t.stringify(s.ciphertext);
};
const decrypt = function (e, n) {
    n = n || "0RGF99CtUajPF0Ny";
    const t = CryptoJS.enc.Utf8.parse(n),
    a = CryptoJS.AES.decrypt(e, t, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return CryptoJS.enc.Utf8.stringify(a).toString();
};

//key生成
function create_key(cuuserret,crtraceid){
    var y = cuuserret; //同请求头中CUUSERRET
    var h = crtraceid; //同请求头中CRTRACEID
    var x = h.toString(), T = y.toString(), k = "";
    [2, 11, 22, 23, 29, 30, 33, 36].map((function (e) {
            k += x.charAt(e - 1)
        })),
    [1, 7, 8, 12, 15, 18, 19, 28].map((function (e) {
            k += T.charAt(e - 1)
        }));
    return k
}

//加密
function data_encrypt(key_,data_) {
    const encrypted = encrypt(data_,key_);
    return encrypted
}

//解密(要解密的字符串必须密钥key_对应)
function data_decrypt(key_,data_) {
    const decrypted = decrypt(data_, key_);
    return decrypted
}