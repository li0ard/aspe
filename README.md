<p align="center">
    <a href="https://github.com/li0ard/aspe/">
        <img src="https://raw.githubusercontent.com/li0ard/aspe/main/.github/logo.svg" alt="aspe logo" title="aspe" width="120" /><br>
    </a><br>
    <b>@li0ard/aspe</b><br>
    <b>simple library for Ariadne Signature Profile (ASP)</b>
    <!--<br>
    <a href="https://li0ard.is-cool.dev/aspe">docs</a>-->
    <br><br>
    <a href="https://github.com/li0ard/aspe/actions/workflows/test.yml"><img src="https://github.com/li0ard/aspe/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/aspe/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/aspe" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/aspe"><img src="https://img.shields.io/npm/v/@li0ard/aspe" /></a>
    <a href="https://jsr.io/@li0ard/aspe"><img src="https://jsr.io/badges/@li0ard/aspe" /></a>
    <br>
    <hr>
</p>

## Features

- Simple: Hides decoding process and provides simple and modern API
- Type-Safe: Most of the APIs are strictly typed to help your workflow
- Compliance: Complies with [Ariadne Signature Profile v0](https://ariadne.id/related/ariadne-signature-profile-0)
- Supports Bun, Node.js, Deno, Browsers, Cloudflare Workers
- Supports ES256 lightweight keypairs and profile/request JWS

## Installation

```bash
# from NPM
npm i @li0ard/aspe

# from JSR
bunx jsr add @li0ard/aspe 
```

## Usage
### Create profile
```ts
import { ASPProfile, SecretKey } from "@li0ard/aspe";

const key = SecretKey.generate();
const profile = new ASPProfile(
    key.publicKey,
    "Alice",
    "Hello, B0b",
    ["dns:domain.tld?type=txt", "https://domain.tld/@alice"],
    "#6855c3"
);
profile.sign(key);

console.log(`New profile: ${profile.name} with ${profile.claims.length} claims`);
console.log(`Thumbprint: ${profile.thumbprint}`);
console.log(`Avatar URL: ${profile.getAvatarUrl()}`);
console.log(`Direct proof: ${profile.getURI()}`);
console.log(`Hashed proof: ${await profile.getHashedProof()}`);
```

### Import profile
```ts
import { ASPProfile } from "@li0ard/aspe";

const base64 = `eyJ0eX....UdqxQ`;
const profile = ASPProfile.fromBase64(base64);

console.log(`Imported profile: ${profile.name}`);
console.log(`- Description: ${profile.description}`);
console.log(`- Claims: ${profile.claims.join(", ")}`);
console.log(`- Color: ${profile.color}`);
```

### Import/Export password-protected secret key
```ts
import { SecretKey } from "@li0ard/aspe";

const secretKey = await SecretKey.fromBase64("ey....n0=", "MYCOOLPASSWORD");

console.log(secretKey);

console.log(await secretKey.toBase64("MYSTRONGESTPASSWORD123!@#$%"));
```