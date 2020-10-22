import * as jwt from 'jsonwebtoken'

import {HttpClient} from '@actions/http-client'
import {BearerCredentialHandler} from '@actions/http-client/auth'

import {Profile, ProfileCreateRequest} from './models/profiles'
import {ResultList, Result} from './models/result'
import {Certificate} from './models/certificates'
import {BundleId} from './models/bundleIds'
import {Device} from './models/devices'
import {AppStoreConnectCredentials} from './credentials'

export interface AppStoreConnectClient {
  /**
   * Find and list provisioning profiles and download their data.
   */
  listProfiles(): Promise<ResultList<Profile> | null>

  /**
   * Get information for a specific provisioning profile and download its data.
   * @param id The id of the profile to download.
   */
  getProfile(id: string): Promise<Result<Profile> | null>

  /**
   * Create a new provisioning profile.
   * @param createRequest The request body you use to create a Profile.
   */
  createProfile(createRequest: ProfileCreateRequest): Promise<Result<Profile> | null>

  listCertificates(): Promise<ResultList<Certificate> | null>

  listBundleIds(): Promise<ResultList<BundleId> | null>

  getBundleId(id: string): Promise<Result<BundleId> | null>

  listDevices(): Promise<ResultList<Device> | null>
}

export class DefaultAppStoreConnectClient implements AppStoreConnectClient {
  /**
   * Construct a DefaultAppStoreConnectClient
   */

  static create(credentials: AppStoreConnectCredentials): DefaultAppStoreConnectClient {
    return new DefaultAppStoreConnectClient(credentials)
  }

  credentials: AppStoreConnectCredentials

  constructor(credentials: AppStoreConnectCredentials) {
    this.credentials = credentials
  }

  async listProfiles(): Promise<ResultList<Profile> | null> {
    const client = this.createClient()
    return await this.list<Profile>(client, `https://api.appstoreconnect.apple.com/v1/profiles`)
  }

  async getProfile(id: string): Promise<Result<Profile> | null> {
    const client = this.createClient()
    return await this.get<Profile>(client, `https://api.appstoreconnect.apple.com/v1/profiles/${id}`)
  }

  async createProfile(createRequest: ProfileCreateRequest): Promise<Result<Profile> | null> {
    const client = this.createClient()
    return await this.create<ProfileCreateRequest, Profile>(client, 'https://api.appstoreconnect.apple.com/v1/profiles', createRequest)
  }

  async listCertificates(): Promise<ResultList<Certificate> | null> {
    const client = this.createClient()
    return await this.list<Certificate>(client, `https://api.appstoreconnect.apple.com/v1/certificates`)
  }

  async listBundleIds(): Promise<ResultList<BundleId> | null> {
    const client = this.createClient()
    return await this.list<BundleId>(client, `https://api.appstoreconnect.apple.com/v1/bundleIds`)
  }

  async getBundleId(id: string): Promise<Result<BundleId> | null> {
    const client = this.createClient()
    return await this.get<BundleId>(client, `https://api.appstoreconnect.apple.com/v1/bundleIds/${id}`)
  }

  async listDevices(): Promise<ResultList<Device> | null> {
    const client = this.createClient()
    return await this.list<Device>(client, `https://api.appstoreconnect.apple.com/v1/devices`)
  }

  createClient(): HttpClient {
    const payload = {iss: this.credentials.issuer, exp: Math.floor(Date.now() / 1000) + 60 * 60, aud: 'appstoreconnect-v1'}
    const header = {kid: this.credentials.keyId}
    const token = jwt.sign(payload, this.credentials.key, {algorithm: 'ES256', header})
    const handlers = [new BearerCredentialHandler(token)]
    return new HttpClient('devbotsxyz/fetch-provisioning-profiles', handlers)
  }

  async list<T>(client: HttpClient, url: string): Promise<ResultList<T> | null> {
    const response = await client.getJson<ResultList<T>>(url)
    if (response.statusCode !== 200) {
      if (response.statusCode === 404) {
        return null
      }
      throw Error(`Received a non-200 response: ${response.statusCode}`)
    }
    return response.result
  }

  async get<T>(client: HttpClient, url: string): Promise<Result<T> | null> {
    const response = await client.getJson<Result<T>>(url)
    if (response.statusCode !== 200) {
      if (response.statusCode === 404) {
        return null
      }
      throw Error(`Received a non-200 response: ${response.statusCode}`)
    }
    return response.result
  }

  async create<CR, R>(client: HttpClient, url: string, createRequest: CR): Promise<Result<R> | null> {
    const response = await client.postJson<Result<R>>(url, createRequest)
    if (response.statusCode !== 201) {
      throw Error(`Received a non-201 response: ${response.statusCode}`)
    }
    return response.result
  }
}
