import {BundleIdPlatform} from '../../appstoreconnect'
import {ResourceLinks} from './common'

enum DeviceClass {
  APPLE_WATCH = 'APPLE_WATCH',
  IPAD = 'IPAD',
  IPHONE = 'IPHONE',
  IPOD = 'IPOD',
  APPLE_TV = 'APPLE_TV',
  MAC = 'MAC'
}

enum DeviceStatus {
  ENABLED = 'ENABLED',
  DISABLED = 'DISABLED'
}

export interface Device {
  type: 'devices'
  id: string
  attributes: {
    deviceClass: DeviceClass
    model: string
    name: string
    platform: BundleIdPlatform
    status: DeviceStatus
    udid: string
    addedDate: Date
  }
  links: ResourceLinks
}

export interface DeviceRelationship {
  type: 'devices'
  id: string
}
