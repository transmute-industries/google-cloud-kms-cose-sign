

import { importSPKI, exportJWK, JWK } from 'jose'

import { KeyManagementServiceClient } from '@google-cloud/kms'

import { formatJwk } from '../formatJwk'

export type RequestPublicKeyByName = {
  name: string;
  client: KeyManagementServiceClient
}

export type PublicKey = JWK & { alg: 'ES256' }

const googleAlgorithmNamesToCoseNames = {
  'EC_SIGN_P384_SHA384': 'ES384',
  'EC_SIGN_P256_SHA256': 'ES256'
} as Record<string, string>

export const getPublicKey = async ({ name, client }: RequestPublicKeyByName) => {
  const [publicKey] = await client.getPublicKey({
    name,
  })
  if (!publicKey.pem) {
    throw new Error('Not a PEM public key')
  }
  if (!publicKey.algorithm) {
    throw new Error('No algorithm assigned to public key')
  }
  if (publicKey) {
    const alg = googleAlgorithmNamesToCoseNames[publicKey.algorithm]
    const importedPublicKey = await importSPKI(publicKey.pem, alg);
    const publicKeyJwk = await exportJWK(importedPublicKey);
    return formatJwk({ ...publicKeyJwk, alg }) as PublicKey
  }
  throw new Error('Could not get public key by name')
}


