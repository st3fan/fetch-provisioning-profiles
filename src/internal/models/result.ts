import {PagedDocumentLinks, PagingInformation, DocumentLinks} from './common'

export interface ResultList<T> {
  data: T[]
  links: PagedDocumentLinks
  meta: PagingInformation
  // TODO 'included' but maybe we simply don't want to support this
}

export interface Result<T> {
  data: T
  links: DocumentLinks
  // TODO 'included' but maybe we simply don't want to support this
}
