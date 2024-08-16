
import crypto from 'crypto'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import format from 'ecdsa-sig-formatter'
export type RequestGoogleCloudKMSSigner = {
  alg: 'ES256' | 'ES384',
  name: string;
  client: KeyManagementServiceClient
}

const coseAlgToNodeCryptHash = {
  'ES384': 'sha384',
  'ES256': 'sha256'
} as Record<'ES256' | 'ES384', string>

export const signer = ({ alg, name, client }: RequestGoogleCloudKMSSigner): { sign: (bytes: ArrayBuffer) => Promise<ArrayBuffer> } => {
  return {
    sign: async (bytes: ArrayBuffer) => {
      const hashName = coseAlgToNodeCryptHash[alg]
      const digest = crypto.createHash(hashName)
      digest.update(Buffer.from(bytes))
      let digestParams
      if (alg === 'ES256') {
        digestParams = {
          sha256: digest.digest(),
        }
      } else if (alg === 'ES384') {
        digestParams = {
          sha384: digest.digest(),
        }
      }
      const [{ signature }] = await client.asymmetricSign({
        name: name,
        digest: digestParams,
      })
      if (!signature) {
        throw new Error('Failed to sign message')
      }
      return Buffer.from(format.derToJose(Buffer.from(signature), alg), 'base64')
    },
  }
}


