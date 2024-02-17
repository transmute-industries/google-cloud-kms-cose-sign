### COSE Signatures

#### with Google Cloud Key Management Service

[![CI](https://github.com/transmute-industries/google-cloud-kms-cose-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/google-cloud-kms-cose-sign/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

## Usage

🔥 This package is not stable or suitable for production use 🚧

```bash
nvm use 18
npm install '@transmute/google-cloud-kms-cose-sign'
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

// Sign a message with a remote private key
const coseSign1 = await cose.detached
  .signer({
    remote: kms.signer({
      alg: "ES384",
      name,
      client,
    }),
  })
  .sign({
    protectedHeader: new Map([
      [
        1,
        -35, // alg: ES384
      ],
    ]),
    unprotectedHeader: new Map(),
    payload,
  });

// Verify a message
const verified = await cose.detached
  .verifier({
    resolver: {
      resolve: async (coseSign1: ArrayBuffer) => {
        const {
          tag,
          value: [protectedHeader],
        } = await cose.cbor.decode(coseSign1);
        if (tag !== 18) {
          throw new Error("Only cose-sign1 are supported");
        }
        const header = await cose.cbor.decode(protectedHeader);
        if (header.get(1) !== -35) {
          throw new Error("Only ES384 signatures are supported");
        }
        // Normally you would check kid / iss
        // and look up the public key from a cache
        // but you can resolve the public key from Google KMS
        // by name, like this:
        return kms.getPublicKeyByName({
          name,
          client,
        });
      },
    },
  })
  .verify({
    coseSign1,
    payload,
  });
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```
