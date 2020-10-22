import {ResourceLinks} from './common'
import {BundleIdPlatform} from './bundleIds'

export enum CertificateType {
  IOS_DEVELOPMENT = 'IOS_DEVELOPMENT',
  IOS_DISTRIBUTION = 'IOS_DISTRIBUTION',
  MAC_APP_DISTRIBUTION = 'MAC_APP_DISTRIBUTION',
  MAC_INSTALLER_DISTRIBUTION = 'MAC_INSTALLER_DISTRIBUTION',
  MAC_APP_DEVELOPMENT = 'MAC_APP_DEVELOPMENT',
  DEVELOPER_ID_KEXT = 'DEVELOPER_ID_KEXT',
  DEVELOPER_ID_APPLICATION = 'DEVELOPER_ID_APPLICATION',
  DEVELOPMENT = 'DEVELOPMENT',
  DISTRIBUTION = 'DISTRIBUTION'
}

export interface Certificate {
  type: 'certificates'
  id: string
  attributes: {
    certificateContent: string
    displayName: string
    expirationDate: Date
    name: string
    platform: BundleIdPlatform
    serialNumber: string
    certificateType: CertificateType
  }
  links: ResourceLinks
}
