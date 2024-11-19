let dataChannel = null
let telemetryChannel = null
let keySuite;
let keySuiteOtherParty;

let rtcConfig = {
    bundlePolicy: "max-bundle",
    iceServers: [
        { urls: 'stun:stun3.l.google.com:19305' }
    ],
    certificates: []
};
let connection;

function resetFields() {
    document.getElementById('createInviteText').value = '';
    document.getElementById('remoteInvite').value = '';
    document.getElementById('createdAnswerInvite').value = '';
    document.getElementById('remoteAnswerInvite').value = '';
}

window.onload = async function () {
    resetFields();

    // Generate keySuite (ECDSA and ECDH keypairs)
    keySuite = await genKeySuite();
    let publicKeys = {
        ECDH: await window.crypto.subtle.exportKey("jwk", keySuite.ECDH.publicKey),
        ECDSA: await window.crypto.subtle.exportKey("jwk", keySuite.ECDSA.publicKey)
    }
    console.log("Public keys", publicKeys)
    // Poll working STUN servers
    // Thanks for this currated list to https://github.com/pradt2
    // https://github.com/pradt2/always-online-stun
    const resp = await fetch('https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt');
    if (resp.status == 200) {
        const rawList = await resp.text();
        const list = rawList.split("\n");
        let liveServers = []
        for (let i = 0; i < 4; i++) {
            let server = {
                urls: 'stun:' + list[i]
            }
            liveServers.push(server)
        }
        rtcConfig.iceServers = liveServers
    } else {
        console.log("Working STUN servers poll failed, fallback to Google!")
    }

    let cert = await RTCPeerConnection.generateCertificate({
        name: "ECDSA",
        namedCurve: "P-256"
    })
    rtcConfig.certificates.push(cert)

    connection = new RTCPeerConnection(rtcConfig);

    connection.onconnectionstatechange = (event) => (document.getElementById('connectionState').innerText = connection.connectionState)
    connection.oniceconnectionstatechange = (event) => (document.getElementById('iceConnectionState').innerText = connection.iceConnectionState)

    dataChannel = connection.createDataChannel('data')
    telemetryChannel = connection.createDataChannel('telemetry')

    dataChannel.onopen = async (event) => {
        document.getElementById('message').disabled = false;
        document.getElementById('sendMessage').disabled = false;
    }

    dataChannel.onmessage = event => messageHandler("system", event)

    telemetryChannel.onopen = async (event) => {
        document.getElementById('message').disabled = false;
        document.getElementById('sendMessage').disabled = false;
        telemetryChannel.send(await enc("ping"))
    }

    telemetryChannel.onmessage = event => telemetryHandler(event)

    connection.ondatachannel = async (event) => {
        const fp = await fingerprint(keySuite, keySuiteOtherParty);
        document.getElementById('fingerprint').innerText = fp;
        document.getElementById('pgpWords').innerText = await PGPWords(fp);

        switch (event.channel.label) {
            case "telemetry":
                event.channel.onmessage = (ev) => telemetryHandler(ev)
                break;

            case "data":
                event.channel.onmessage = (ev) => messageHandler("stranger", ev)
                break;
        }

    }
};

async function telemetryHandler(event) {
    const payload = JSON.parse(event.data)

    if (!payload.hasOwnProperty('msg') && !payload.hasOwnProperty('sign')) {
        return alert("Unencrypted or uncorrect message arrived!!!")
    }

    const plaintext = await dec(payload);
    switch (plaintext) {
        case "ping":
            logContent("system", "Connection Established");
            console.log("ping")
            telemetryChannel.send(await enc("pong"));
            break;
        case "pong":
            logContent("system", "Connection Established");
            console.log("pong")
            break;
        default:
            break;
    }
}

async function messageHandler(user, event) {
    const payload = JSON.parse(event.data)
    if (!payload.hasOwnProperty('msg') && !payload.hasOwnProperty('sign')) {
        return alert("Unencrypted or uncorrect message arrived!!!")
    }
    const plaintext = await dec(payload);


    return logContent(user, plaintext);
    //return alert(plaintext);
}

async function logContent(user, content) {
    let time = getTime();
    const newContent = document.getElementById("chatBox").innerHTML + time +
        ` <${user}>: ` + content + "&#10;";

    return document.getElementById("chatBox").innerHTML = newContent;
}

function getTime() {
    let date = new Date();

    let hour = date.getHours();
    let min = date.getMinutes();
    let sec = date.getSeconds();

    if (hour < 10) {
        hour = "0" + hour;
    }
    if (min < 10) {
        min = "0" + min;
    }
    if (sec < 10) {
        sec = "0" + sec;
    }
    return `${hour}:${min}:${sec}`;
}

async function createInvite() {
    document.getElementById('remoteInvite').disabled = true
    document.getElementById('acceptOffer').disabled = true

    document.getElementById('remoteAnswerInvite').disabled = false
    document.getElementById('acceptAnswerInvite').disabled = false

    connection.onicecandidate = async (event) => {
        if (!event.candidate) {
            const invite = {
                ECDH: await window.crypto.subtle.exportKey("jwk", keySuite.ECDH.publicKey),
                ECDSA: await window.crypto.subtle.exportKey("jwk", keySuite.ECDSA.publicKey),
                SDP: connection.localDescription
            }

            document.getElementById('createInviteText').value = btoa(JSON.stringify(invite))
            document.getElementById('createInviteText').hidden = false
        }
    }

    const offer = await connection.createOffer()
    await connection.setLocalDescription(offer);
}

async function acceptInvite() {
    document.getElementById('createInvite').disabled = true;

    const inviteCode = JSON.parse(atob(document.getElementById('remoteInvite').value))
    keySuiteOtherParty = {
        ECDH: await window.crypto.subtle.importKey("jwk", inviteCode.ECDH, { name: "ECDH", namedCurve: "P-256" }, true, []),
        ECDSA: await window.crypto.subtle.importKey("jwk", inviteCode.ECDSA, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"])
    }

    console.log("Other party public keys: ", { ECDH: inviteCode.ECDH, ECDSA: inviteCode.ECDSA })
    await connection.setRemoteDescription(inviteCode.SDP)

    connection.onicecandidate = async (event) => {
        if (!event.candidate) {
            document.getElementById('remoteInvite').disabled = true

            const inviteAnswer = {
                ECDH: await window.crypto.subtle.exportKey("jwk", keySuite.ECDH.publicKey),
                ECDSA: await window.crypto.subtle.exportKey("jwk", keySuite.ECDSA.publicKey),
                SDP: connection.localDescription
            }

            document.getElementById('createdAnswerInvite').value = btoa(JSON.stringify(inviteAnswer))
            document.getElementById('createdAnswerInvite').hidden = false
        }
    }

    const answer = await connection.createAnswer()
    await connection.setLocalDescription(answer)
}

async function acceptAnswer() {
    document.getElementById('createInvite').disabled = true
    document.getElementById('createInvite').disabled = true
    document.getElementById('remoteAnswerInvite').disabled = true
    document.getElementById('acceptAnswerInvite').disabled = true
    const answer = JSON.parse(atob(document.getElementById('remoteAnswerInvite').value))
    keySuiteOtherParty = {
        ECDH: await window.crypto.subtle.importKey("jwk", answer.ECDH, { name: "ECDH", namedCurve: "P-256" }, true, []),
        ECDSA: await window.crypto.subtle.importKey("jwk", answer.ECDSA, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
    }
    console.log("Other party public keys: ", { ECDH: answer.ECDH, ECDSA: answer.ECDSA })
    await connection.setRemoteDescription(answer.SDP)
}

async function send() {
    const msg = await enc(document.getElementById('message').value);
    dataChannel.send(msg)
    logContent("you", document.getElementById('message').value);
}

async function dec(payload) {
    let plaintext;
    try {
        plaintext = await msgDecryptAndVerify(payload, keySuite.ECDH.privateKey, keySuiteOtherParty.ECDH, keySuiteOtherParty.ECDSA);
    } catch (e) {
        console.log("Error: ", e)
        return
    }
    return plaintext;
}

async function enc(plaintext) {
    return JSON.stringify(await msgEncryptAndSign(plaintext, keySuite.ECDH.privateKey, keySuiteOtherParty.ECDH, keySuite.ECDSA.privateKey))
}