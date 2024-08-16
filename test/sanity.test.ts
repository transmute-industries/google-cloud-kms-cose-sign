// eslint-disable-next-line @typescript-eslint/no-var-requires
require('dotenv').config();
import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as cose from '@transmute/cose'
import * as kms from '../src'

describe.skip('google cloud platform', () => {

  const name = process.env.GOOGLE_KMS_KEY_NAME || ''
  const email = process.env.GOOGLE_SA_EMAIL || ''
  const private_key = process.env.GOOGLE_SA_PRIVATE_KEY || ''
  const message = `⌛ My lungs taste the air of Time Blown past falling sands ⌛`
  const payload = new TextEncoder().encode(message)

  const client = new KeyManagementServiceClient({
    credentials: {
      client_email: email,
      private_key: private_key.replace(/\\n/g, '\n')
    }
  })
  it('export public key', async () => {
    const publicKeyJwk = await kms.jose.getPublicKey({ client, name })
    expect(publicKeyJwk.crv).toBe('P-256')
    expect(publicKeyJwk.alg).toBe('ES256')
  })

  it('sign / verify', async () => {
    const coseSign1 = await cose
      .signer({
        remote: await kms.cose.remote({ client, name, alg: 'ES256' })
      })
      .sign({
        protectedHeader: cose.ProtectedHeader([
          [cose.Protected.Alg, cose.Signature.ES256],
        ]),
        payload,
      })
    const verified = await kms.cose
      .verifier({ client, name })
      .verify({
        coseSign1
      })
    expect(new TextDecoder().decode(verified)).toBe(message)
  })
})
