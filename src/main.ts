import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as core from '@actions/core'

import {createAppStoreConnectClientFromInputs, ProfileType, ProfileCreateRequest} from './appstoreconnect'
import {BundleIdPlatform} from './internal/models/bundleIds'

const supportedProfileTypes = [
  ProfileType.IOS_APP_DEVELOPMENT,
  ProfileType.IOS_APP_STORE,
  ProfileType.MAC_APP_DEVELOPMENT,
  ProfileType.MAC_APP_DIRECT,
  ProfileType.MAC_APP_STORE
]

async function run(): Promise<void> {
  try {
    const client = createAppStoreConnectClientFromInputs()

    const profileType = core.getInput('profile-type', {required: true}) as ProfileType
    if (!supportedProfileTypes.includes(profileType)) {
      throw Error(`Invalid profile-type <${profileType}>; only <${supportedProfileTypes.join(', ')}> are currently supported.`)
    }

    const bundleIdentifiers = core.getInput('bundle-identifier', {required: true})

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

      const profileCreateRequest: ProfileCreateRequest = {
        data: {
          type: 'profiles',
          attributes: {
            name: `DevBots: iOS App Store Profile: ${identifier}`,
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
              data: [] // TODO Do we need the distribution certificate here?
            }
          }
        }
      }

      const createProfileResult = await client.createProfile(profileCreateRequest)
      if (createProfileResult === null) {
        throw Error(`Failed to create profile for ${identifier}`)
      }

      const decodedProfile = Buffer.from(createProfileResult.data.attributes.profileContent, 'base64')

      const provisioningProfilesPath = path.join(os.homedir(), 'Library/MobileDevice/Provisioning Profiles')
      const profileExtension = bundleId.attributes.platform === BundleIdPlatform.MAC_OS ? 'provisionprofile' : 'mobileprovision'
      const profileName = `${createProfileResult.data.attributes.uuid}.${profileExtension}`

      core.info(`Creating ${provisioningProfilesPath}`)
      fs.mkdirSync(provisioningProfilesPath, {recursive: true})

      core.info(`Writing <${profileType}> provisioning profile for <${identifier}> to <${path}>`)
      fs.writeFileSync(path.join(provisioningProfilesPath, profileName), decodedProfile)
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()
