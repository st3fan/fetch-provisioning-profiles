/**
 * Self-links to documents that can contain information for one or more resources.
 */

export interface DocumentLinks {
  /** The link that produced the current document. */
  self: string
}

/**
 * The links to the related data and the relationship's self-link.
 */

export interface Links {
  related: string
  /** The link that produced the current document. */
  self: string
}

/**
 * Links related to the response document, including paging links.
 */

export interface PagedDocumentLinks {
  /** The link that produced the current document. */
  self: string
  /** The link to the first page of documents. */
  first?: string
  /** The link to the next page of documents. */
  next?: string
}

/**
 * Self-links to requested resources.
 */

export interface ResourceLinks {
  /** The link that produced the current document. */
  self: string
}

/**
 * Paging details such as the total number of resources and the per-page limit.
 */

export interface PagingInformationPaging {
  /** The total number of resources matching your request. */
  total: number
  /** The maximum number of resources to return per page, from 0 to 200. */
  limit: number
}

/**
 * Paging information for data responses.
 */

export interface PagingInformation {
  /** The paging information details. */
  paging: PagingInformationPaging
}
