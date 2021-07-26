// Configuration:
const clientId = "";
const clientSecret = "";
//const accessTokenUri = "https://auth.dev.chicagoartcc.org/oauth/token";
//const authorizationUri = "https://auth.dev.chicagoartcc.org/oauth/authorize";
//const accessTokenUri = "http://local.chicagoartcc.org:3000/oauth/token";
//const authorizationUri = "http://local.chicagoartcc.org:3000/oauth/authorize";
const accessTokenUri = "https://auth.chicagoartcc.org/oauth/token";
const authorizationUri = "https://auth.chicagoartcc.org/oauth/authorize";
const redirectUri = "http://local.chicagoartcc.org:8000/callback";

const express = require("express")
const app = express()
const session = require("express-session");
const port = 8000
const { nanoid } = require("nanoid")
const clientoauth = require("client-oauth2");
const auth = new clientoauth({
  clientId: clientId,
  clientSecret: clientSecret,
  accessTokenUri: accessTokenUri,
  authorizationUri: authorizationUri,
  redirectUri: redirectUri,
  scopes: ["all"],
  state: nanoid(21),
});
const crypto = require('crypto');

function toBase64UrlEncoded(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function generateCodeVerifier() {
    return toBase64UrlEncoded(crypto.randomBytes(32));
};

function createCodeChallenge(codeVerifier) {
        return toBase64UrlEncoded(
            crypto.createHash("sha256")
                .update(codeVerifier, "ascii")
                .digest("base64")
        )
}

let codeVerifier = generateCodeVerifier();
let codeChallenge = createCodeChallenge(codeVerifier);

app.use(session({secret:"testenv", cookie: {}}))

app.get("/", (req, res) => {
    res.send("Hello")
});

app.get("/login", (req, res) => {
    req.session.code_verifier = nanoid(32);
    req.session.state = nanoid(21);

    let uri = auth.code.getUri({
        state: req.session.state,
        query: {
//            code_challenge_method: "S256",
//            code_challenge: createCodeChallenge(req.session.code_verifier),
            response_type: "code",
        }
    });

    res.redirect(uri);
});

app.get("/callback", (req, res) => {
    console.log(req.query)
    auth.code.getToken(req.originalUrl, {
        state: req.session.state,
        body: {
//            code_verifier: req.session.code_verifier,
            client_secret: clientSecret,
            client_id: clientId,
        }
    }).then((resp) => {
        console.log(resp);
        res.send("OK, access token " + resp.accessToken);
    }).catch((err) => {
        console.error(`Error received ${err}`);
        res.send("Error");
    });
});

app.listen(port, () => {
    console.log("Listening.")
})
