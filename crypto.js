async function msgEncryptAndSign(msg, privateKey, publicKey, privateKeyECDH){
    let ciphertext = await msgEncryptBasedECDH(msg, privateKey, publicKey);
    let sig = await sign(ciphertext, privateKeyECDH);
    return { msg: ciphertext, sig}
}

async function msgDecryptAndVerify(payload, privateKeyECDH, publicKeyECDH, publicKeyECDSA){
    const result = await verify(payload.msg, payload.sig, publicKeyECDSA);
    if (!result){
        return new Error('Verification failed');
    }
    let plaintext = await msgDecryptBasedECDH(payload.msg, privateKeyECDH, publicKeyECDH);
    return plaintext;
}

async function msgEncryptBasedECDH(msg, privateKey, publicKey) {
    let secret = await deriveSecretKeyToECDH(privateKey, publicKey);
    let ciphertext = await encrypt(secret, msg);
    secret = "";
    return ciphertext;
}

async function msgDecryptBasedECDH(msg, privateKey, publicKey) {
    let secret = await deriveSecretKeyToECDH(privateKey, publicKey);
    let plaintext = await decrypt(hex2buf(msg), secret);
    secret = "";
    return plaintext;
}

async function exportKeySuite(keySuite) {
    return {
        ECDH: await window.crypto.subtle.exportKey("jwk", keySuite.ECDH.publicKey),
        ECDSA: await window.crypto.subtle.exportKey("jwk", keySuite.ECDSA.publicKey)
    }
}

async function genKeySuite() {
    let ecdh = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        ["deriveKey"]
    );

    let ecdsa = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        false,
        ["sign", "verify"]
    );
    return { ECDH: ecdh, ECDSA: ecdsa }
}

async function sign(msg, privateKey){
    let enc = new TextEncoder();
    let signature = await window.crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: { name: "SHA-512" },
        },
        privateKey,
        enc.encode(msg)
    );
    return buf2hex(signature)
}

async function verify(msg, sig, publicKey) {
    let enc = new TextEncoder();
    let result = await window.crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-512" },
        },
        publicKey,
        hex2buf(sig),
        enc.encode(msg)
    )
    return result
}

async function encrypt(secretKey, msg) {
    let iv = window.crypto.getRandomValues(new Uint8Array(12));
    let enc = new TextEncoder();
    let ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        secretKey,
        enc.encode(msg)
    );
    enc = "";
    const struct = Uint8Array.from([...iv, ...new Uint8Array(ciphertext)])    
    return buf2hex([...struct])
}

async function decrypt(msg, secretKey){
    try {
        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: msg.slice(0, 12)
            },
            secretKey,
            msg.slice(12, msg.length)
        );
        secretKey = "";
        let dec = new TextDecoder();
        return dec.decode(decrypted)
    } catch (e) {
        return e
    }
}

function deriveSecretKeyToECDH(privateKey, publicKey) {
    return window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: publicKey
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hex2buf(msg) {
    let bytes = new Uint8Array(Math.ceil(msg.length / 2));
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(msg.substr(i * 2, 2), 16);
    return bytes;
}

async function wrapKey(format, keyToWrap, password) {

    let { wrappingKey, salt } = await deriveKeyToWrappingKey(password);

    let iv = window.crypto.getRandomValues(new Uint8Array(12));

    let wrappedKey = await window.crypto.subtle.wrapKey(
        format,
        keyToWrap,
        wrappingKey,
        {
            name: "AES-GCM",
            iv: iv
        }
    );

    const struct = Uint8Array.from([...iv, ...new Uint8Array(wrappedKey), ...new Uint8Array(salt)])
    return buf2hex([...struct])

}

async function deriveKeyToWrappingKey(password) {
    const enc = new TextEncoder();
    
    let kdf = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    let salt = window.crypto.getRandomValues(new Uint8Array(16));

    let wrappingKey = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt,
            "iterations": 100000,
            "hash": "SHA-256"
        },
        kdf,
        { "name": "AES-GCM", "length": 256 },
        true,
        ["wrapKey", "unwrapKey"]
    );

    return { wrappingKey, salt }
}