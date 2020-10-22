import {PagingInformation, PagedDocumentLinks} from './common'

export enum BundleIdPlatform {
  IOS = 'IOS',
  MAC_OS = 'MAC_OS',
  UNIVERSAL = 'UNIVERSAL' // TODO This is not documented
}

export interface BundleId {
  type: 'bundleIds'
  id: string
  attributes: {
    name: string
    identifier: string
    platform: BundleIdPlatform
    seedId: string
  }
  relationships: {
    bundleIdCapabilities: {
      meta: PagingInformation
      links: PagedDocumentLinks
      data: {
        id: string
        type: string
      }[]
    }
    profiles: {
      meta: PagingInformation
      links: PagedDocumentLinks
      data: {
        id: string
        type: string
      }[]
    }
    app: {
      links: PagedDocumentLinks
      data: {
        id: string
        type: string
      }
    }
  }
}
