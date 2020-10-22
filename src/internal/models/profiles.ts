import {BundleIdPlatform} from './bundleIds'
import {PagingInformation, Links} from './common'

export enum ProfileState {
  ACTIVE = 'ACTIVE',
  INVALID = 'INVALID'
}

export enum ProfileType {
  IOS_APP_DEVELOPMENT = 'IOS_APP_DEVELOPMENT',
  IOS_APP_STORE = 'IOS_APP_STORE',
  IOS_APP_ADHOC = 'IOS_APP_ADHOC',
  IOS_APP_INHOUSE = 'IOS_APP_INHOUSE',
  MAC_APP_DEVELOPMENT = 'MAC_APP_DEVELOPMENT',
  MAC_APP_STORE = 'MAC_APP_STORE',
  MAC_APP_DIRECT = 'MAC_APP_DIRECT',
  TVOS_APP_DEVELOPMENT = 'TVOS_APP_DEVELOPMENT',
  TVOS_APP_STORE = 'TVOS_APP_STORE',
  TVOS_APP_ADHOC = 'TVOS_APP_ADHOC',
  TVOS_APP_INHOUSE = 'TVOS_APP_INHOUSE',
  MAC_CATALYST_APP_DEVELOPMENT = 'MAC_CATALYST_APP_DEVELOPMENT',
  MAC_CATALYST_APP_STORE = 'MAC_CATALYST_APP_STORE',
  MAC_CATALYST_APP_DIRECT = 'MAC_CATALYST_APP_DIRECT'
}

export interface Profile {
  type: 'profiles'
  id: string
  attributes: {
    name: string
    platform: BundleIdPlatform
    profileContent: string
    uuid: string
    createdDate: Date
    profileState: ProfileState
    profileType: ProfileType
    expirationDate: Date
  }
  relationships: {
    certificates: {
      data: {
        id: string
        type: string
      }[]
      meta: PagingInformation
      links: Links
    }
    devices: {
      data: {
        id: string
        type: string
      }[]
      meta: PagingInformation
      links: Links
    }
    bundleId: {
      data: {
        id: string
        type: string
      }
      links: Links
    }
  }
}

export interface ProfileCreateRequest {
  data: {
    attributes: {
      name: string
      profileType: ProfileType
    }
    relationships: {
      bundleId: {
        data: {
          id: string
          type: 'bundleIds'
        }
      }
      certificates: {
        data: {
          id: string
          type: 'certificates'
        }[]
      }
    }
    devices?: {
      data: {
        id: string
        type: string
      }[]
    }
    type: 'profiles'
  }
}
