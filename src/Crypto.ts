import CryptoJS from 'crypto-js'

export class Crypto {
  /**
   * Encrypt data
   * @param {string} data data
   * @param {string} password password
   * @return {string} encrypt string
   */
  public static decrypt(data: string, password: string): string {
    const salt = CryptoJS.enc.Hex.parse(data.slice(0, 32))
    const iv = CryptoJS.enc.Hex.parse(data.slice(32, 64))
    const encrypted = data.slice(64)

    // generate password based key
    const key = CryptoJS.PBKDF2(password, salt, {
      iterations: 1024,
      keySize: 8,
    })

    // decrypt using custom IV
    const decrypted = CryptoJS.AES.decrypt(encrypted, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    })

    return decrypted.toString(CryptoJS.enc.Utf8)
  }

  /**
   * Encrypt data
   * @param {string} data data
   * @param {string} password password
   * @return {string} decrypt string
   */
  public static encrypt(data: string, password: string): string {
    const salt = CryptoJS.lib.WordArray.random(16)

    // generate password based key
    const key = CryptoJS.PBKDF2(password, salt, {
      iterations: 1024,
      keySize: 8,
    })

    // encrypt using random IV
    const iv = CryptoJS.lib.WordArray.random(16)
    const encrypted = CryptoJS.AES.encrypt(data, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    })

    // salt (16 bytes) + iv (16 bytes)
    // prepend them to the ciphertext for use in decryption
    return salt.toString() + iv.toString() + encrypted.toString()
  }
}
