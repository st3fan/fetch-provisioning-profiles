import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as core from '@actions/core'

import {
  createAppStoreConnectClientFromInputs,
  AppStoreConnectClient,
  BundleId,
  Profile,
  ProfileType,
  ProfileCreateRequest,
  CertificateRelationship,
  DeviceRelationship
} from './appstoreconnect'

import {BundleIdPlatform} from './internal/models/bundleIds'
import {CertificateType} from './internal/models/certificates'

const supportedProfileTypes = [
  ProfileType.IOS_APP_DEVELOPMENT,
  ProfileType.IOS_APP_STORE,
  ProfileType.MAC_APP_DEVELOPMENT,
  ProfileType.MAC_APP_DIRECT,
  ProfileType.MAC_APP_STORE
]

async function findProfile(client: AppStoreConnectClient, bundleId: BundleId, profileType: ProfileType): Promise<Profile | null> {
  const listProfilesResponse = await client.listProfiles()
  if (listProfilesResponse !== null) {
    for (const profile of listProfilesResponse.data) {
      if (profile.attributes.name === 'DevBots: Mac App Development Profile: ca.hogtownsoftware.examples.HelloMac.HelloMac') {
        return profile
      }
    }
  }
  return null
}

async function createProfile(client: AppStoreConnectClient, bundleId: BundleId, profileType: ProfileType): Promise<Profile> {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(bundleId, null, 2))

  const certificates: CertificateRelationship[] = []
  if (profileType === ProfileType.MAC_APP_DEVELOPMENT || profileType === ProfileType.IOS_APP_DEVELOPMENT) {
    const listCertificatesResponse = await client.listCertificates()
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(listCertificatesResponse, null, 2))

    if (listCertificatesResponse !== null) {
      for (const certificate of listCertificatesResponse?.data) {
        if (certificate.attributes.certificateType === CertificateType.DEVELOPMENT) {
          certificates.push({type: 'certificates', id: certificate.id})
          // TODO Not checking this because certificate.attributes.platform is null ?
          // if (profileType === ProfileType.MAC_APP_DEVELOPMENT && certificate.attributes.platform === BundleIdPlatform.MAC_OS) {
          //   certificates.push({type: 'certificates', id: certificate.id})
          // }
          // if (profileType === ProfileType.IOS_APP_DEVELOPMENT && certificate.attributes.platform === BundleIdPlatform.IOS) {
          //   certificates.push({type: 'certificates', id: certificate.id})
          // }
        }
      }
    }
    if (certificates.length === 0) {
      throw Error(`Profile type ${profileType} requires registered development certificates.`)
    }
  }

  const devices: DeviceRelationship[] = []
  if (profileType === ProfileType.MAC_APP_DEVELOPMENT || profileType === ProfileType.IOS_APP_DEVELOPMENT) {
    const listDevicesResponse = await client.listDevices()

    // eslint-disable-next-line no-console
    console.log(JSON.stringify(listDevicesResponse, null, 2))

    if (listDevicesResponse !== null) {
      for (const device of listDevicesResponse?.data) {
        if (profileType === ProfileType.MAC_APP_DEVELOPMENT && device.attributes.platform === BundleIdPlatform.MAC_OS) {
          devices.push({type: 'devices', id: device.id})
        }
        if (profileType === ProfileType.IOS_APP_DEVELOPMENT && device.attributes.platform === BundleIdPlatform.IOS) {
          devices.push({type: 'devices', id: device.id})
        }
      }
    }
    if (devices.length === 0) {
      throw Error(`Profile type ${profileType} requires registered development devices.`)
    }
  }

  const profileCreateRequest: ProfileCreateRequest = {
    data: {
      type: 'profiles',
      attributes: {
        name: `DevBots: Mac App Development Profile: ${bundleId.attributes.identifier}`,
        profileType
      },
      relationships: {
        bundleId: {
          data: {
            type: 'bundleIds',
            id: bundleId.id
          }
        },
        certificates: {
          data: certificates, // [{type: 'certificates', id: '56UGYQJX93'}]
        },
        devices: {
          data: devices
        }
      }
    }
  }

  // eslint-disable-next-line no-console
  console.log(JSON.stringify(profileCreateRequest, null, 2))

  const createProfileResult = await client.createProfile(profileCreateRequest)
  if (createProfileResult === null) {
    throw Error(`Failed to create profile for ${bundleId.attributes.identifier}`)
  }

  return createProfileResult.data
}

async function run(): Promise<void> {
  try {
    const client = createAppStoreConnectClientFromInputs()

    const profileType = core.getInput('profile-type', {required: true}) as ProfileType
    if (!supportedProfileTypes.includes(profileType)) {
      throw Error(`Invalid profile-type <${profileType}>; only <${supportedProfileTypes.join(', ')}> are currently supported.`)
    }

    const bundleIdentifiers = core.getInput('bundle-identifiers', {required: true}).split(',')

    // We don't search properly using the API so we simply grab all available bundle ids now.
    const listBundleIdsResponse = await client.listBundleIds()
    if (listBundleIdsResponse === null || listBundleIdsResponse.data.length === 0) {
      throw Error('No Bundle Identifiers (Application IDs) were found')
    }

    for (const identifier of bundleIdentifiers) {
      const bundleId = listBundleIdsResponse.data.find(b => {
        return b.attributes.identifier === identifier
      })
      if (bundleId === undefined) {
        throw Error(`Cannot find bundle identifier ${identifier}`)
      }

      // Make sure the platform matches. With watchOS and tvOS this is probably more complicated, but we can save that for later.

      if (profileType.startsWith('IOS_APP_') && ![BundleIdPlatform.IOS, BundleIdPlatform.UNIVERSAL].includes(bundleId.attributes.platform)) {
        throw Error(`Cannot use profile-type <${profileType}> with bundleId platform <${bundleId.attributes.platform}>`)
      }
      if (profileType.startsWith('IOS_APP_') && ![BundleIdPlatform.MAC_OS, BundleIdPlatform.UNIVERSAL].includes(bundleId.attributes.platform)) {
        throw Error(`Cannot use profile-type <${profileType}> with bundleId platform <${bundleId.attributes.platform}>`)
      }

      let profile = await findProfile(client, bundleId, profileType)
      if (profile === null) {
        profile = await createProfile(client, bundleId, profileType)
      }

      // Write it to disk

      const decodedProfile = Buffer.from(profile.attributes.profileContent, 'base64')

      const provisioningProfilesPath = path.join(os.homedir(), 'Library/MobileDevice/Provisioning Profiles')
      // TODO Find out if this actually matters - maybe xcodebuild doesn't care
      const profileExtension =
        bundleId.attributes.platform === BundleIdPlatform.MAC_OS || bundleId.attributes.platform === BundleIdPlatform.UNIVERSAL
          ? 'provisionprofile'
          : 'mobileprovision'
      const profileName = `${profile.attributes.uuid}.${profileExtension}`

      core.info(`Creating ${provisioningProfilesPath}`)
      fs.mkdirSync(provisioningProfilesPath, {recursive: true})

      core.info(`Writing <${profileType}> provisioning profile for <${identifier}> to <${profileName}>`)
      fs.writeFileSync(path.join(provisioningProfilesPath, profileName), decodedProfile)

      // Testing if the extension is important or not
      fs.writeFileSync(path.join(provisioningProfilesPath, `${profile.attributes.uuid}.mobileprovision`), decodedProfile)
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()
