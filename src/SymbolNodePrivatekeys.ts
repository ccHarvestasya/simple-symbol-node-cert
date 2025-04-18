import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'fs'
import { Crypto } from './Crypto.js'
import { dump, load } from 'js-yaml'
import { PrivatekeysYaml } from './ModelPrivatekeysYaml.js'
import { execSync } from 'child_process'

export class SymbolNodePrivatekeys {
  /**
   * 秘密鍵暗号化
   * @param inPrivatekyesPath 入力秘密鍵保存ファイル
   * @param outPrivatekyesPath 出力秘密鍵保存ファイル
   * @param passwd パスワード
   */
  encrypt(inPrivatekyesPath: string, outPrivatekyesPath: string, passwd: string) {
    /** privatekeysファイル読み込み */
    let privatekeysYaml: PrivatekeysYaml
    try {
      const privatekeys = readFileSync(inPrivatekyesPath)
      privatekeysYaml = load(privatekeys.toString()) as PrivatekeysYaml
    } catch {
      throw Error(`ファイルの読み込みに失敗しました。： ${inPrivatekyesPath}`)
    }

    /** 秘密鍵暗号化 */
    // CA
    const caPriKeyHex = privatekeysYaml.main?.privateKey
    const caPriKeyEnc = caPriKeyHex ? Crypto.encrypt(caPriKeyHex, passwd) : undefined
    // Node
    const nodePriKeyHex = privatekeysYaml.transport?.privateKey
    const nodePriKeyEnc = nodePriKeyHex ? Crypto.encrypt(nodePriKeyHex, passwd) : undefined

    /** 書き込み */
    const newPrivatekeysYaml: PrivatekeysYaml = {}
    if (caPriKeyEnc) {
      newPrivatekeysYaml.main = {
        privateKey: caPriKeyEnc,
        publicKey: privatekeysYaml.main?.publicKey,
      }
    }
    if (nodePriKeyEnc) {
      newPrivatekeysYaml.transport = {
        privateKey: nodePriKeyEnc,
        publicKey: privatekeysYaml.transport?.publicKey,
      }
    }
    try {
      writeFileSync(outPrivatekyesPath, dump(newPrivatekeysYaml))
    } catch {
      throw Error(`ファイルの書き込みに失敗しました。: ${outPrivatekyesPath}`)
    }
  }

  /**
   * 秘密鍵復号化
   * @param inPrivatekyesPath 入力秘密鍵保存ファイル
   * @param outPrivatekyesPath 出力秘密鍵保存ファイル
   * @param passwd パスワード
   */
  decrypt(inPrivatekyesPath: string, outPrivatekyesPath: string, passwd: string) {
    /** privatekeysファイル読み込み */
    let privatekeysYaml: PrivatekeysYaml
    try {
      const privatekeys = readFileSync(inPrivatekyesPath)
      privatekeysYaml = load(privatekeys.toString()) as PrivatekeysYaml
    } catch {
      throw Error(`ファイルの読み込みに失敗しました。： ${inPrivatekyesPath}`)
    }

    /** 秘密鍵復号 */
    // CA
    let caPriKeyHex = ''
    const caPriKeyEnc = privatekeysYaml.main?.privateKey ?? undefined
    if (caPriKeyEnc) {
      const caPriKeyDec = Crypto.decrypt(caPriKeyEnc, passwd)
      caPriKeyHex = caPriKeyDec !== '' ? caPriKeyDec : caPriKeyEnc
      if (caPriKeyHex.length !== 64) {
        throw Error('平文CA秘密鍵の長さが64桁ではありません。')
      }
    }
    // Node
    let nodePriKeyHex = ''
    const nodePriKeyEnc = privatekeysYaml.transport?.privateKey ?? undefined
    if (nodePriKeyEnc) {
      const nodePriKeyDec = Crypto.decrypt(nodePriKeyEnc, passwd)
      nodePriKeyHex = nodePriKeyDec !== '' ? nodePriKeyDec : nodePriKeyEnc
      if (nodePriKeyHex.length !== 64) {
        throw Error('平文Node秘密鍵の長さが64桁ではありません。')
      }
    }

    /** 書き込み */
    const newPrivatekeysYaml: PrivatekeysYaml = {}
    if (caPriKeyEnc) {
      newPrivatekeysYaml.main = {
        privateKey: caPriKeyHex,
        publicKey: privatekeysYaml.main?.publicKey,
      }
    }
    if (nodePriKeyEnc) {
      newPrivatekeysYaml.transport = {
        privateKey: nodePriKeyHex,
        publicKey: privatekeysYaml.transport?.publicKey,
      }
    }
    try {
      writeFileSync(outPrivatekyesPath, dump(newPrivatekeysYaml))
    } catch {
      throw Error(`ファイルの書き込みに失敗しました。: ${outPrivatekyesPath}`)
    }
  }

  /**
   * パスワード変更
   * @param inPrivatekyesPath 入力秘密鍵保存ファイル
   * @param outPrivatekyesPath 出力秘密鍵保存ファイル
   * @param oldPasswd 旧パスワード
   * @param newPasswd 新パスワード
   */
  changePasswd(inPrivatekyesPath: string, outPrivatekyesPath: string, oldPasswd: string, newPasswd: string) {
    this.decrypt(inPrivatekyesPath, outPrivatekyesPath, oldPasswd)
    this.encrypt(outPrivatekyesPath, outPrivatekyesPath, newPasswd)
  }

  /**
   * 秘密鍵を暗号化してファイルに書き込む
   * @param writePrivatekyesPath 出力ファイル
   * @param caPriKeyPath CA秘密鍵パス
   * @param nodePriKeyPath Node秘密鍵パス
   * @param passwd パスワード
   */
  encryptPrivateKey(writePrivatekyesPath: string, caPriKeyPath: string, nodePriKeyPath: string, passwd: string) {
    /** 秘密鍵 */
    // CA
    const caPriKeyBase64 = this.getPrivatekeyFromPrikeyFile(caPriKeyPath)
    let caPriKeyHex = Buffer.from(caPriKeyBase64, 'base64').toString('hex').toUpperCase()
    caPriKeyHex = caPriKeyHex.substring(caPriKeyHex.length - 64, caPriKeyHex.length)
    const caPriKeyEnc = Crypto.encrypt(caPriKeyHex, passwd)
    // Node
    const nodePriKeyBase64 = this.getPrivatekeyFromPrikeyFile(nodePriKeyPath)
    let nodePriKeyHex = Buffer.from(nodePriKeyBase64, 'base64').toString('hex').toUpperCase()
    nodePriKeyHex = nodePriKeyHex.substring(nodePriKeyHex.length - 64, nodePriKeyHex.length)
    const nodePriKeyEnc = Crypto.encrypt(nodePriKeyHex, passwd)

    /** 公開鍵 */
    // CA
    const caPubKeyBase64 = this.getPublickeyFromPrikeyFile(caPriKeyPath)
    let caPubKeyHex = Buffer.from(caPubKeyBase64, 'base64').toString('hex').toUpperCase()
    caPubKeyHex = caPubKeyHex.substring(caPubKeyHex.length - 64, caPubKeyHex.length)
    // Node
    const nodePubKeyBase64 = this.getPublickeyFromPrikeyFile(nodePriKeyPath)
    let nodePubKeyHex = Buffer.from(nodePubKeyBase64, 'base64').toString('hex').toUpperCase()
    nodePubKeyHex = nodePubKeyHex.substring(nodePubKeyHex.length - 64, nodePubKeyHex.length)

    /** privatekeysファイル保存 */
    const privatekeysYaml: PrivatekeysYaml = {
      main: {
        privateKey: caPriKeyEnc,
        publicKey: caPubKeyHex,
      },
      transport: {
        privateKey: nodePriKeyEnc,
        publicKey: nodePubKeyHex,
      },
    }
    this.writeFile(writePrivatekyesPath, dump(privatekeysYaml))

    // 秘密鍵削除
    this.deleteFile(caPriKeyPath)
    // Node秘密鍵はソケット通信で使用するので削除しない
    // this.deleteFile(nodePriKeyPath)
  }

  /**
   * 暗号化された秘密鍵を秘密鍵ファイルに戻す
   * @param writePrivatekyesPath 出力ファイル
   * @param caPriKeyPath CA秘密鍵パス
   * @param nodePriKeyPath Node秘密鍵パス
   * @param passwd パスワード
   */
  decryptPrivateKey(readPrivatekyesPath: string, caPriKeyPath: string, nodePriKeyPath: string, passwd: string) {
    const prikeyPrefix = '302E020100300506032B657004220420'

    /** privatekeysファイル読み込み */
    const privatekeys = readFileSync(readPrivatekyesPath)
    const privatekeysYaml = load(privatekeys.toString()) as PrivatekeysYaml

    /** 秘密鍵 */
    // CA
    const caPriKeyEnc = privatekeysYaml.main?.privateKey ?? ''
    let caPriKeyBase64 = ''
    if (caPriKeyEnc !== '') {
      const caPriKeyDec = Crypto.decrypt(caPriKeyEnc, passwd)
      let caPriKeyHex = caPriKeyDec !== '' ? caPriKeyDec : caPriKeyEnc
      if (caPriKeyHex.length === 64) {
        caPriKeyHex = prikeyPrefix + caPriKeyHex
      } else {
        throw Error('平文CA秘密鍵の長さが64桁ではありません。')
      }
      caPriKeyBase64 = Buffer.from(caPriKeyHex, 'hex').toString('base64')
    }
    // Node
    const nodePriKeyEnc = privatekeysYaml.transport?.privateKey ?? ''
    let nodePriKeyBase64 = ''
    if (nodePriKeyEnc !== '') {
      const nodePriKeyDec = Crypto.decrypt(nodePriKeyEnc, passwd)
      let nodePriKeyHex = nodePriKeyDec !== '' ? nodePriKeyDec : nodePriKeyEnc
      if (nodePriKeyHex.length === 64) {
        nodePriKeyHex = prikeyPrefix + nodePriKeyHex
      } else {
        throw Error('平文Node秘密鍵の長さが64桁ではありません。')
      }
      nodePriKeyBase64 = Buffer.from(nodePriKeyHex, 'hex').toString('base64')
    }

    /** 秘密鍵書き込み */
    if (caPriKeyBase64 !== '') this.writePrivatekey(caPriKeyPath, caPriKeyBase64)
    if (!existsSync(nodePriKeyPath)) {
      if (nodePriKeyBase64 !== '') this.writePrivatekey(nodePriKeyPath, nodePriKeyBase64)
    }
  }

  /**
   * 秘密鍵ファイルからBase64公開鍵取得
   * @param priKeyPath 秘密鍵パス
   * @returns Base64公開鍵
   */
  private getPublickeyFromPrikeyFile(priKeyPath: string) {
    const pubkey = execSync(`openssl pkey -in ${priKeyPath} -pubout`)
    const pubkeyString = pubkey.toString().replaceAll('\r\n', '\n').replaceAll('\r', '\n')
    const pubkeyMatch = pubkeyString.match(/^(.*)$/gm)
    return pubkeyMatch ? pubkeyMatch[1] : ''
  }

  /**
   * 秘密鍵ファイルからBase64秘密鍵取得
   * @param priKeyPath 秘密鍵パス
   * @returns Base64秘密鍵
   */
  private getPrivatekeyFromPrikeyFile(priKeyPath: string) {
    let prikey
    try {
      prikey = readFileSync(priKeyPath)
    } catch (e) {
      throw Error(`ファイルの読み込みに失敗しました。: ${priKeyPath}`)
    }
    const prikeyString = prikey.toString().replaceAll('\r\n', '\n').replaceAll('\r', '\n')
    const prikeyMatch = prikeyString.match(/^(.*)$/gm)
    return prikeyMatch ? prikeyMatch[1] : ''
  }

  /**
   * 秘密鍵書き込み
   * @param priKeyPath 秘密鍵パス
   * @param prikeyBase64 秘密鍵値
   */
  private writePrivatekey(priKeyPath: string, prikeyBase64: string) {
    const privatekey = `-----BEGIN PRIVATE KEY-----
${prikeyBase64}
-----END PRIVATE KEY-----
`
    this.writeFile(priKeyPath, privatekey)
    chmodSync(priKeyPath, 0o600)
  }

  /**
   * ファイルの書き込み
   * @param filePath ファイルパス
   * @param fileData ファイルデータ
   */
  private writeFile(filePath: string, fileData: string) {
    try {
      writeFileSync(filePath, fileData)
    } catch {
      throw Error(`ファイルの保存に失敗しました。: ${filePath}`)
    }
  }

  /**
   * ファイルの削除
   * @param filePath ファイルパス
   */
  private deleteFile(filePath: string) {
    try {
      unlinkSync(filePath)
    } catch {
      throw Error(`ファイルの削除に失敗しました。: ${filePath}`)
    }
  }
}
