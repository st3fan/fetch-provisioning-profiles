import * as core from '@actions/core'

import {AppStoreConnectClient, DefaultAppStoreConnectClient} from './internal/client'
import {AppStoreConnectCredentials} from './internal/credentials'
import {Profile, ProfileType, ProfileCreateRequest} from './internal/models/profiles'
import {BundleId, BundleIdPlatform} from './internal/models/bundleIds'
import {Certificate, CertificateRelationship} from './internal/models/certificates'
import {Device, DeviceRelationship} from './internal/models/devices'

function credentialsFromInputs(): AppStoreConnectCredentials {
  const encodedKey = core.getInput('appstore-connect-api-key', {required: true})
  const key = Buffer.from(encodedKey, 'base64').toString()
  const keyId = core.getInput('appstore-connect-api-key-id', {required: true})
  const issuer = core.getInput('appstore-connect-api-issuer', {required: true})
  return {key, keyId, issuer}
}

export function createAppStoreConnectClientFromInputs(): AppStoreConnectClient {
  return DefaultAppStoreConnectClient.create(credentialsFromInputs())
}

export {AppStoreConnectClient}
export {Profile, ProfileType, ProfileCreateRequest}
export {BundleId, BundleIdPlatform}
export {Certificate, CertificateRelationship}
export {Device, DeviceRelationship}
