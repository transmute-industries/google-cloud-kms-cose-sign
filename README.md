### COSE Signatures

#### with Google Cloud Key Management Service

[![CI](https://github.com/transmute-industries/google-cloud-kms-cose-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/google-cloud-kms-cose-sign/actions/workflows/ci.yml)

## Usage

🔥 This package is not stable or suitable for production use 🚧

```bash
nvm use 18
npm install @transmute/google-cloud-kms-cose-sign
```

```ts
import { KeyManagementServiceClient } from "@google-cloud/kms";
import * as kms from "@transmute/google-cloud-kms-cose-sign";
import * as cose from "@transmute/cose";

const name = process.env.GOOGLE_KMS_KEY_NAME || "";
const email = process.env.GOOGLE_SA_EMAIL || "";
const private_key = process.env.GOOGLE_SA_PRIVATE_KEY || "";
const message = `⌛ My lungs taste the air of Time Blown past falling sands ⌛`;
const payload = new TextEncoder().encode(message);
const client = new KeyManagementServiceClient({
  credentials: {
    client_email: email,
    private_key: private_key.replace(/\\n/g, "\n"),
  },
});

const coseSign1 = await cose
  .signer({
    remote: await kms.cose.remote({ client, name, alg: "ES256" }),
  })
  .sign({
    protectedHeader: cose.ProtectedHeader([
      [cose.Protected.Alg, cose.Signature.ES256],
    ]),
    payload,
  });

const verified = await kms.cose.verifier({ client, name }).verify({
  coseSign1,
});
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
