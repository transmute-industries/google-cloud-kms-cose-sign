import { KeyManagementServiceClient } from '@google-cloud/kms'
import { JWK } from 'jose'
import { signer } from '../signer';

import * as cose from '@transmute/cose'

import { getPublicKey } from '../jose';

export type RequestRemoteSigner = {
  name: string;
  client: KeyManagementServiceClient,
  alg: 'ES384' | 'ES256'
}

export const remote = (req: RequestRemoteSigner) => {
  return {
    sign: async (bytes: ArrayBuffer) => {
      return signer(req).sign(bytes)
    }
  }
}

export type RequestRemoteVerifier = {
  name: string;
  client: KeyManagementServiceClient,
  alg: 'ES384' | 'ES256'
}

export type RequestCoseKidVerifier = {
  client: KeyManagementServiceClient,
  name: string,
}

export type RequestCosePublicKeyVerifier = {
  publicKeyJwk: JWK & { alg: 'ES256' }
}

export type RequestCoseVerifier = RequestCoseKidVerifier | RequestCosePublicKeyVerifier


export const verifier = (req: RequestCoseVerifier) => {
  if ((req as RequestCosePublicKeyVerifier).publicKeyJwk) {
    const { publicKeyJwk } = req as RequestCosePublicKeyVerifier
    return cose.verifier({
      resolver: {
        resolve: async () => {
          return publicKeyJwk
        }
      }
    })
  } else if ((req as RequestCoseKidVerifier)) {
    const { client, name } = req as RequestCoseKidVerifier
    return cose.verifier({
      resolver: {
        resolve: async () => {
          const publicKeyJwk = await getPublicKey({ client, name })
          return publicKeyJwk
        }
      }
    })
  }
  throw new Error('COSE verifier requires public key or kid and credential')
}