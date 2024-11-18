// High-level API for cryptographic operations
async function msgEncryptAndSign(msg, privateKey, publicKey, privateKeyECDH) {
    let ciphertext = await msgEncryptBasedECDH(msg, privateKey, publicKey);
    let sig = await sign(ciphertext, privateKeyECDH);
    return { msg: ciphertext, sig }
}

async function msgDecryptAndVerify(payload, privateKeyECDH, publicKeyECDH, publicKeyECDSA) {
    const result = await verify(payload.msg, payload.sig, publicKeyECDSA);
    if (!result) {
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

async function generateKey(params, extractable, keyUsages) {
    return await window.crypto.subtle.generateKey(params, extractable, keyUsages);
}

async function sign(msg, privateKey) {
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

async function legacyEncrypt(secretKey, msg) {
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

async function legacyDecrypt(msg, secretKey) {
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

async function encryptAESGCM(key, plaintext){
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        plaintext
    );

    const struct = Uint8Array.from([...iv, ...new Uint8Array(ciphertext)])
    return buf2hex([...struct])
}

async function decryptAESGCM(key, bundle){
    const ivLength = 12;
    if (bundle.length <= ivLength) {
        return new Error('Invalid bundle, length must be at least 12 bytes');
    }

    const cipherBundle = hex2buf(bundle);
    const iv = cipherBundle.slice(0, ivLength);
    const ciphertext = cipherBundle.slice(ivLength, cipherBundle.length);

    let decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );

    return decrypted;
}

// Key Wrapping Utils

async function deriveKeyToWrappingKey(password, iteration, hash) {
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
            "salt": salt,
            "iterations": iteration,
            "hash": hash
        },
        kdf,
        { "name": "AES-GCM", "length": 256 },
        false,
        ["wrapKey"]
    );

    return { wrappingKey, salt }
}

async function wrapKey(format, keyToWrap, password, iteration, hash) {

    let { wrappingKey, salt } = await deriveKeyToWrappingKey(password, iteration, hash);

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

async function deriveKeyToUnwrappingKey(password, salt, iteration, hash) {
    const enc = new TextEncoder();

    let kdf = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    let unwrappingKey = await window.crypto.subtle.deriveKey(
    {
        "name": "PBKDF2",
        "salt": salt,
        "iterations": iteration,
        "hash": hash
    },
    kdf,
    { "name": "AES-GCM", "length": 256 },
    false,
    ["unwrapKey"]
    );

    return unwrappingKey;
}

async function unwrapKey(format, keyToUnwrap, password, iteration, hash){
    const ivLength = 12;
    const saltLength = 16;

    if (keyToUnwrap.length <= ivLength + saltLength) {
        return new Error('Invalid wrapped key, length must be at least 28 bytes');
    }

    const wrappedBundle = hex2buf(keyToUnwrap);

    const iv = wrappedBundle.slice(0, ivLength);
    const wrappedKey = wrappedBundle.slice(ivLength, wrappedBundle.length - saltLength);
    const salt = wrappedBundle.slice(wrappedBundle.length - saltLength, wrappedBundle.length);
    
    const kek = await deriveKeyToUnwrappingKey(password, salt, iteration, hash);

    let unwrappedKey = await window.crypto.subtle.unwrapKey(
        format,
        wrappedKey,
        kek,
        {
            name: "AES-GCM",
            iv: iv
        },
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
    return unwrappedKey;
}


// Generic Utils

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

function bytesToArrayBuffer(bytes) {
    const bytesAsArrayBuffer = new ArrayBuffer(bytes.length);
    const bytesUint8 = new Uint8Array(bytesAsArrayBuffer);
    bytesUint8.set(bytes);
    return bytesAsArrayBuffer;
}

function arrayBufferToBytes(buffer) {
    return new Uint8Array(buffer);
}


function stringToArrayBuffer(str) {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(str);
    return uint8Array.buffer;
}

function arrayBufferToString(buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

async function rfc7638EC(publicKey) {
    let lexOrder = {};

    lexOrder.crv = publicKey.crv
    lexOrder.kty = publicKey.kty
    lexOrder.x = publicKey.x
    lexOrder.y = publicKey.y
    const data = new TextEncoder().encode(JSON.stringify(lexOrder));

    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return buf2hex(hash);
}

async function calculatePBKDF2Iterations(timeInSeconds) {
    const password = "correct horse battery staple";
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const iterations = 1000000; // Start with a base iteration count
    const start = performance.now();

    await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const end = performance.now();
    const timeTaken = end - start;

    const iterationsPerSecond = iterations / (timeTaken / 1000);
    const totalIterations = Math.floor(iterationsPerSecond * timeInSeconds);

    return totalIterations;
}


// "Fingerprint" Utils

function PGPWords(fingerprint){
    let words = "";
    let j = 0;
    for (let i = 0; i < fingerprint.length-1; i+=2) {
        const hex = fingerprint[i].concat(fingerprint[i+1]);
        words += `${raw_words[hex][j%2]} `;
        j++;
    }

    return words;
}

async function fingerprint(keySuite, keySuiteOtherParty) {
    const rootObject = [];
    const publicKeys = [keySuite.ECDH.publicKey, keySuite.ECDSA.publicKey, keySuiteOtherParty.ECDH, keySuiteOtherParty.ECDSA]

    for (let i = 0; i < publicKeys.length; i++) {
        const exportedPublicKey = await window.crypto.subtle.exportKey("jwk", publicKeys[i])
        const hashedPublicKey = await rfc7638EC(exportedPublicKey);
        rootObject.push(hashedPublicKey);
    }
    const data = new TextEncoder().encode(JSON.stringify(rootObject.sort()));
    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return buf2hex(hash).toUpperCase()
}

const raw_words = {
    '00': ['aardvark', 'adroitness'],
    '01': ['absurd', 'adviser'],
    '02': ['accrue', 'aftermath'],
    '03': ['acme', 'aggregate'],
    '04': ['adrift', 'alkali'],
    '05': ['adult', 'almighty'],
    '06': ['afflict', 'amulet'],
    '07': ['ahead', 'amusement'],
    '08': ['aimless', 'antenna'],
    '09': ['Algol', 'applicant'],
    '0A': ['allow', 'Apollo'],
    '0B': ['alone', 'armistice'],
    '0C': ['ammo', 'article'],
    '0D': ['ancient', 'asteroid'],
    '0E': ['apple', 'Atlantic'],
    '0F': ['artist', 'atmosphere'],
    '10': ['assume', 'autopsy'],
    '11': ['Athens', 'Babylon'],
    '12': ['atlas', 'backwater'],
    '13': ['Aztec', 'barbecue'],
    '14': ['baboon', 'belowground'],
    '15': ['backfield', 'bifocals'],
    '16': ['backward', 'bodyguard'],
    '17': ['banjo', 'bookseller'],
    '18': ['beaming', 'borderline'],
    '19': ['bedlamp', 'bottomless'],
    '1A': ['beehive', 'Bradbury'],
    '1B': ['beeswax', 'bravado'],
    '1C': ['befriend', 'Brazilian'],
    '1D': ['Belfast', 'breakaway'],
    '1E': ['berserk', 'Burlington'],
    '1F': ['billiard', 'businessman'],
    '20': ['bison', 'butterfat'],
    '21': ['blackjack', 'Camelot'],
    '22': ['blockade', 'candidate'],
    '23': ['blowtorch', 'cannonball'],
    '24': ['bluebird', 'Capricorn'],
    '25': ['bombast', 'caravan'],
    '26': ['bookshelf', 'caretaker'],
    '27': ['brackish', 'celebrate'],
    '28': ['breadline', 'cellulose'],
    '29': ['breakup', 'certify'],
    '2A': ['brickyard', 'chambermaid'],
    '2B': ['briefcase', 'Cherokee'],
    '2C': ['Burbank', 'Chicago'],
    '2D': ['button', 'clergyman'],
    '2E': ['buzzard', 'coherence'],
    '2F': ['cement', 'combustion'],
    '30': ['chairlift', 'commando'],
    '31': ['chatter', 'company'],
    '32': ['checkup', 'component'],
    '33': ['chisel', 'concurrent'],
    '34': ['choking', 'confidence'],
    '35': ['chopper', 'conformist'],
    '36': ['Christmas', 'congregate'],
    '37': ['clamshell', 'consensus'],
    '38': ['classic', 'consulting'],
    '39': ['classroom', 'corporate'],
    '3A': ['cleanup', 'corrosion'],
    '3B': ['clockwork', 'councilman'],
    '3C': ['cobra', 'crossover'],
    '3D': ['commence', 'crucifix'],
    '3E': ['concert', 'cumbersome'],
    '3F': ['cowbell', 'customer'],
    '40': ['crackdown', 'Dakota'],
    '41': ['cranky', 'decadence'],
    '42': ['crowfoot', 'December'],
    '43': ['crucial', 'decimal'],
    '44': ['crumpled', 'designing'],
    '45': ['crusade', 'detector'],
    '46': ['cubic', 'detergent'],
    '47': ['dashboard', 'determine'],
    '48': ['deadbolt', 'dictator'],
    '49': ['deckhand', 'dinosaur'],
    '4A': ['dogsled', 'direction'],
    '4B': ['dragnet', 'disable'],
    '4C': ['drainage', 'disbelief'],
    '4D': ['dreadful', 'disruptive'],
    '4E': ['drifter', 'distortion'],
    '4F': ['dropper', 'document'],
    '50': ['drumbeat', 'embezzle'],
    '51': ['drunken', 'enchanting'],
    '52': ['Dupont', 'enrollment'],
    '53': ['dwelling', 'enterprise'],
    '54': ['eating', 'equation'],
    '55': ['edict', 'equipment'],
    '56': ['egghead', 'escapade'],
    '57': ['eightball', 'Eskimo'],
    '58': ['endorse', 'everyday'],
    '59': ['endow', 'examine'],
    '5A': ['enlist', 'existence'],
    '5B': ['erase', 'exodus'],
    '5C': ['escape', 'fascinate'],
    '5D': ['exceed', 'filament'],
    '5E': ['eyeglass', 'finicky'],
    '5F': ['eyetooth', 'forever'],
    '60': ['facial', 'fortitude'],
    '61': ['fallout', 'frequency'],
    '62': ['flagpole', 'gadgetry'],
    '63': ['flatfoot', 'Galveston'],
    '64': ['flytrap', 'getaway'],
    '65': ['fracture', 'glossary'],
    '66': ['framework', 'gossamer'],
    '67': ['freedom', 'graduate'],
    '68': ['frighten', 'gravity'],
    '69': ['gazelle', 'guitarist'],
    '6A': ['Geiger', 'hamburger'],
    '6B': ['glitter', 'Hamilton'],
    '6C': ['glucose', 'handiwork'],
    '6D': ['goggles', 'hazardous'],
    '6E': ['goldfish', 'headwaters'],
    '6F': ['gremlin', 'hemisphere'],
    '70': ['guidance', 'hesitate'],
    '71': ['hamlet', 'hideaway'],
    '72': ['highchair', 'holiness'],
    '73': ['hockey', 'hurricane'],
    '74': ['indoors', 'hydraulic'],
    '75': ['indulge', 'impartial'],
    '76': ['inverse', 'impetus'],
    '77': ['involve', 'inception'],
    '78': ['island', 'indigo'],
    '79': ['jawbone', 'inertia'],
    '7A': ['keyboard', 'infancy'],
    '7B': ['kickoff', 'inferno'],
    '7C': ['kiwi', 'informant'],
    '7D': ['klaxon', 'insincere'],
    '7E': ['locale', 'insurgent'],
    '7F': ['lockup', 'integrate'],
    '80': ['merit', 'intention'],
    '81': ['minnow', 'inventive'],
    '82': ['miser', 'Istanbul'],
    '83': ['Mohawk', 'Jamaica'],
    '84': ['mural', 'Jupiter'],
    '85': ['music', 'leprosy'],
    '86': ['necklace', 'letterhead'],
    '87': ['Neptune', 'liberty'],
    '88': ['newborn', 'maritime'],
    '89': ['nightbird', 'matchmaker'],
    '8A': ['Oakland', 'maverick'],
    '8B': ['obtuse', 'Medusa'],
    '8C': ['offload', 'megaton'],
    '8D': ['optic', 'microscope'],
    '8E': ['orca', 'microwave'],
    '8F': ['payday', 'midsummer'],
    '90': ['peachy', 'millionaire'],
    '91': ['pheasant', 'miracle'],
    '92': ['physique', 'misnomer'],
    '93': ['playhouse', 'molasses'],
    '94': ['Pluto', 'molecule'],
    '95': ['preclude', 'Montana'],
    '96': ['prefer', 'monument'],
    '97': ['preshrunk', 'mosquito'],
    '98': ['printer', 'narrative'],
    '99': ['prowler', 'nebula'],
    '9A': ['pupil', 'newsletter'],
    '9B': ['puppy', 'Norwegian'],
    '9C': ['python', 'October'],
    '9D': ['quadrant', 'Ohio'],
    '9E': ['quiver', 'onlooker'],
    '9F': ['quota', 'opulent'],
    'A0': ['ragtime', 'Orlando'],
    'A1': ['ratchet', 'outfielder'],
    'A2': ['rebirth', 'Pacific'],
    'A3': ['reform', 'pandemic'],
    'A4': ['regain', 'Pandora'],
    'A5': ['reindeer', 'paperweight'],
    'A6': ['rematch', 'paragon'],
    'A7': ['repay', 'paragraph'],
    'A8': ['retouch', 'paramount'],
    'A9': ['revenge', 'passenger'],
    'AA': ['reward', 'pedigree'],
    'AB': ['rhythm', 'Pegasus'],
    'AC': ['ribcage', 'penetrate'],
    'AD': ['ringbolt', 'perceptive'],
    'AE': ['robust', 'performance'],
    'AF': ['rocker', 'pharmacy'],
    'B0': ['ruffled', 'phonetic'],
    'B1': ['sailboat', 'photograph'],
    'B2': ['sawdust', 'pioneer'],
    'B3': ['scallion', 'pocketful'],
    'B4': ['scenic', 'politeness'],
    'B5': ['scorecard', 'positive'],
    'B6': ['Scotland', 'potato'],
    'B7': ['seabird', 'processor'],
    'B8': ['select', 'provincial'],
    'B9': ['sentence', 'proximate'],
    'BA': ['shadow', 'puberty'],
    'BB': ['shamrock', 'publisher'],
    'BC': ['showgirl', 'pyramid'],
    'BD': ['skullcap', 'quantity'],
    'BE': ['skydive', 'racketeer'],
    'BF': ['slingshot', 'rebellion'],
    'C0': ['slowdown', 'recipe'],
    'C1': ['snapline', 'recover'],
    'C2': ['snapshot', 'repellent'],
    'C3': ['snowcap', 'replica'],
    'C4': ['snowslide', 'reproduce'],
    'C5': ['solo', 'resistor'],
    'C6': ['southward', 'responsive'],
    'C7': ['soybean', 'retraction'],
    'C8': ['spaniel', 'retrieval'],
    'C9': ['spearhead', 'retrospect'],
    'CA': ['spellbind', 'revenue'],
    'CB': ['spheroid', 'revival'],
    'CC': ['spigot', 'revolver'],
    'CD': ['spindle', 'sandalwood'],
    'CE': ['spyglass', 'sardonic'],
    'CF': ['stagehand', 'Saturday'],
    'D0': ['stagnate', 'savagery'],
    'D1': ['stairway', 'scavenger'],
    'D2': ['standard', 'sensation'],
    'D3': ['stapler', 'sociable'],
    'D4': ['steamship', 'souvenir'],
    'D5': ['sterling', 'specialist'],
    'D6': ['stockman', 'speculate'],
    'D7': ['stopwatch', 'stethoscope'],
    'D8': ['stormy', 'stupendous'],
    'D9': ['sugar', 'supportive'],
    'DA': ['surmount', 'surrender'],
    'DB': ['suspense', 'suspicious'],
    'DC': ['sweatband', 'sympathy'],
    'DD': ['swelter', 'tambourine'],
    'DE': ['tactics', 'telephone'],
    'DF': ['talon', 'therapist'],
    'E0': ['tapeworm', 'tobacco'],
    'E1': ['tempest', 'tolerance'],
    'E2': ['tiger', 'tomorrow'],
    'E3': ['tissue', 'torpedo'],
    'E4': ['tonic', 'tradition'],
    'E5': ['topmost', 'travesty'],
    'E6': ['tracker', 'trombonist'],
    'E7': ['transit', 'truncated'],
    'E8': ['trauma', 'typewriter'],
    'E9': ['treadmill', 'ultimate'],
    'EA': ['Trojan', 'undaunted'],
    'EB': ['trouble', 'underfoot'],
    'EC': ['tumor', 'unicorn'],
    'ED': ['tunnel', 'unify'],
    'EE': ['tycoon', 'universe'],
    'EF': ['uncut', 'unravel'],
    'F0': ['unearth', 'upcoming'],
    'F1': ['unwind', 'vacancy'],
    'F2': ['uproot', 'vagabond'],
    'F3': ['upset', 'vertigo'],
    'F4': ['upshot', 'Virginia'],
    'F5': ['vapor', 'visitor'],
    'F6': ['village', 'vocalist'],
    'F7': ['virus', 'voyager'],
    'F8': ['Vulcan', 'warranty'],
    'F9': ['waffle', 'Waterloo'],
    'FA': ['wallet', 'whimsical'],
    'FB': ['watchword', 'Wichita'],
    'FC': ['wayside', 'Wilmington'],
    'FD': ['willow', 'Wyoming'],
    'FE': ['woodlark', 'yesteryear'],
    'FF': ['Zulu', 'Yucatan']
}