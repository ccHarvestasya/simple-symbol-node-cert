import { execSync } from 'child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join, resolve } from 'path'
import { SymbolNodePrivatekeys } from './SymbolNodePrivatekeys.js'
import { Address, Network, SymbolFacade } from 'symbol-sdk/symbol'
import { PublicKey } from 'symbol-sdk'

export class SimpleSymbolNodeCert {
  /**
   * Symbolノード証明書発行
   * @param certDirPath 証明書出力ディレクトリ
   * @param caName CA名
   * @param nodeName Node名
   * @param caCertDays CA証明書有効日数
   * @param nodeCertDays Node証明書有効日数
   * @param isForce 上書出力フラグ
   * @param privatekeysFilePath privatekeysファイルパス
   * @param passwd privatekeysファイル暗号化パスワード
   */
  public generate(
    certDirPath: string = './cert',
    caName: string = 'my cool CA',
    nodeName: string = 'my cool node name',
    caCertDays: number = 7300,
    nodeCertDays: number = 375,
    isForce: boolean = false,
    privatekeysFilePath: string = './privatekeys.yaml',
    passwd: string = ''
  ) {
    /** 有効日数チェック */
    if (caCertDays < nodeCertDays) throw Error('CA証明書の有効日数がNode証明書の有効日数より小さいです。')

    /** OpenSSLバージョンチェック */
    this.checkVersionOpenSsl()

    /** パス取得 */
    const certDirPathAbs = resolve(certDirPath)
    const privatekeysFilePathAbs = resolve(privatekeysFilePath)
    const caPriKeyFileName = 'ca.key.pem'
    const nodePriKeyFileName = 'node.key.pem'
    const caPriKeyFilePathAbs = join(certDirPathAbs, caPriKeyFileName)
    const nodePriKeyFilePathAbs = join(certDirPathAbs, nodePriKeyFileName)
    const pubKeyFileName = 'ca.pubkey.pem'
    const pubKeyFilePathAbs = join(certDirPathAbs, pubKeyFileName)

    /** 出力ディレクトリ作成 */
    if (existsSync(certDirPathAbs)) {
      if (!isForce) throw Error(`証明書出力ディレクトリがすでに存在します。: ${certDirPathAbs}`)
      rmSync(certDirPathAbs, { recursive: true })
    }
    mkdirSync(certDirPathAbs, { recursive: true })

    /** privatekeysファイルチェック */
    const snp = new SymbolNodePrivatekeys()
    if (existsSync(privatekeysFilePathAbs)) {
      // 存在する場合秘密鍵を復元
      snp.decryptPrivateKey(privatekeysFilePathAbs, caPriKeyFilePathAbs, nodePriKeyFilePathAbs, passwd)
    }

    /** 秘密鍵生成 */
    if (!existsSync(caPriKeyFilePathAbs)) this.generatePrivateKey(caPriKeyFilePathAbs)
    if (!existsSync(nodePriKeyFilePathAbs)) this.generatePrivateKey(nodePriKeyFilePathAbs)

    /** 設定ファイル作成 */
    this.createCaConfig(certDirPathAbs, caName, caPriKeyFilePathAbs)
    this.createNodeConfig(certDirPathAbs, nodeName)

    /** 公開鍵生成 */
    this.generatePublicKey(caPriKeyFilePathAbs, pubKeyFilePathAbs)

    /** 証明書作成 */
    this.createCaCertificate(certDirPathAbs, caPriKeyFilePathAbs, caCertDays)
    this.createNodeCsr(certDirPathAbs, nodePriKeyFileName)
    this.signingCertificate(certDirPathAbs, nodeCertDays)
    // 証明書連結
    this.createSymbolNodeCert(certDirPathAbs)

    /** privatekeysファイル保存 */
    snp.encryptPrivateKey(privatekeysFilePathAbs, caPriKeyFilePathAbs, nodePriKeyFilePathAbs, passwd)
  }

  /**
   * Symbolノード証明書の期限を更新する
   * @param certDirPath 証明書出力ディレクトリ
   * @param caCertDays CA証明書有効日数
   * @param nodeCertDays Node証明書有効日数
   * @param privatekeysFilePath privatekeysファイルパス
   * @param passwd privatekeysファイル暗号化パスワード
   */
  public renew(
    certDirPath: string = './cert',
    caCertDays: number = 7300,
    nodeCertDays: number = 375,
    privatekeysFilePath: string = './privatekeys.yaml',
    passwd: string = ''
  ) {
    /** 有効日数チェック */
    if (caCertDays < nodeCertDays) throw Error('CA証明書の有効日数がNode証明書の有効日数より小さいです。')

    /** OpenSSLバージョンチェック */
    this.checkVersionOpenSsl()

    /** パス取得 */
    const certDirPathAbs = resolve(certDirPath)
    const privatekeysFilePathAbs = resolve(privatekeysFilePath)
    const caPriKeyFileName = 'ca.key.pem'
    const nodePriKeyFileName = 'node.key.pem'
    const caPriKeyFilePathAbs = join(certDirPathAbs, caPriKeyFileName)
    const nodePriKeyFilePathAbs = join(certDirPathAbs, nodePriKeyFileName)

    /** 出力ディレクトリ作成 */
    if (!existsSync(certDirPathAbs)) {
      throw Error(`証明書出力ディレクトリが存在しません。: ${certDirPathAbs}`)
    }

    /** privatekeysファイルチェック */
    if (existsSync(privatekeysFilePathAbs)) {
      // 存在する場合秘密鍵を復元
      const snp = new SymbolNodePrivatekeys()
      snp.decryptPrivateKey(privatekeysFilePathAbs, caPriKeyFilePathAbs, nodePriKeyFilePathAbs, passwd)
    } else {
      throw Error(`ファイルが存在しないため秘密鍵が復元できません。: ${privatekeysFilePathAbs}`)
    }

    /** 秘密鍵チェック */
    if (!existsSync(caPriKeyFilePathAbs)) throw Error(`CA秘密鍵が存在しません。: ${caPriKeyFilePathAbs}`)
    if (!existsSync(nodePriKeyFilePathAbs)) throw Error(`Node秘密鍵が存在しません。: ${nodePriKeyFilePathAbs}`)

    /** 古いデータベース削除 */
    this.revokeCertificate(certDirPathAbs)

    /** 証明書作成 */
    this.createCaCertificate(certDirPathAbs, caPriKeyFilePathAbs, caCertDays)
    this.createNodeCsr(certDirPathAbs, nodePriKeyFileName)
    this.signingCertificate(certDirPathAbs, nodeCertDays)
    // 証明書連結
    this.createSymbolNodeCert(certDirPathAbs)
  }

  /**
   * Symbolノード証明書の期限と公開鍵表示
   * @param certDirPath 証明書ディレクトリパス
   */
  public info(certDirPath: string = './cert') {
    /** OpenSSLバージョンチェック */
    this.checkVersionOpenSsl()

    /** パス取得 */
    const certDirPathAbs = resolve(certDirPath)

    const certInfo = execSync(
      `openssl crl2pkcs7 -nocrl -certfile node.full.crt.pem | openssl pkcs7 -print_certs -text -noout`,
      {
        cwd: certDirPathAbs,
      }
    )

    /** 開始日 */
    const startDates: Date[] = []
    const startDateMatches = certInfo.toString().matchAll(/Not Before: (.*)/g)
    for (const match of startDateMatches) {
      startDates.push(new Date(match[1]))
    }
    /** 終了日 */
    const endDates: Date[] = []
    const endDateMatches = certInfo.toString().matchAll(/Not After : (.*)/g)
    for (const match of endDateMatches) {
      endDates.push(new Date(match[1]))
    }
    /** 公開鍵 */
    const publicKeys: string[] = []
    const publicKeyMatches = certInfo
      .toString()
      .matchAll(/pub:[\r\n|\n|\r]\s+(.*)[\r\n|\n|\r]\s+(.*)[\r\n|\n|\r]\s+(.*)/g)
    for (const match of publicKeyMatches) {
      let pubKey = match[1] + match[2] + match[3]
      pubKey = pubKey.replaceAll(':', '')
      publicKeys.push(pubKey.toUpperCase())
    }
    /** アドレス */
    const mainFacade = new SymbolFacade(Network.MAINNET)
    const testFacade = new SymbolFacade(Network.TESTNET)
    // Node
    const mainCaAddress = new Address(mainFacade.network.publicKeyToAddress(new PublicKey(publicKeys[0]))).toString()
    const testCaAddress = new Address(testFacade.network.publicKeyToAddress(new PublicKey(publicKeys[0]))).toString()
    // CA
    const mainNodeAddress = new Address(mainFacade.network.publicKeyToAddress(new PublicKey(publicKeys[1]))).toString()
    const testNodeAddress = new Address(testFacade.network.publicKeyToAddress(new PublicKey(publicKeys[1]))).toString()

    console.log(`==================================================`)
    console.log(`CA Cert:`)
    console.log(`       Start Date: ${startDates[1]}`)
    console.log(`         End Date: ${endDates[1]}`)
    console.log(`       Public Key: ${publicKeys[1]}`)
    console.log(`  Mainnet Address: ${mainNodeAddress}`)
    console.log(`  Testnet Address: ${testNodeAddress}`)
    console.log(`Node Cert:`)
    console.log(`       Start Date: ${startDates[0]}`)
    console.log(`         End Date: ${endDates[0]}`)
    console.log(`       Public Key: ${publicKeys[0]}`)
    console.log(`  Mainnet Address: ${mainCaAddress}`)
    console.log(`  Testnet Address: ${testCaAddress}`)
    console.log(`==================================================`)
  }

  /**
   * Symbolノード証明書作成
   * @param outputDir 出力ディレクトリ
   */
  private createSymbolNodeCert(outputDir: string) {
    const caCertFileName = 'ca.crt.pem'
    const nodeCertFileName = 'node.crt.pem'
    const symbolNodeCertFileName = 'node.full.crt.pem'

    const caCert = readFileSync(join(outputDir, caCertFileName), 'utf8')
    const nodeCert = readFileSync(join(outputDir, nodeCertFileName), 'utf8')
    writeFileSync(join(outputDir, symbolNodeCertFileName), nodeCert + caCert)
  }

  /**
   * Node Config 作成
   * @param outputDir 出力ディレクトリ
   * @param nodeName ノード名
   */
  private createNodeConfig(outputDir: string, nodeName: string) {
    console.log('Node Config 作成')

    const nodeConfig = `[req]
prompt = no
distinguished_name = dn
[dn]
CN = ${nodeName}
`
    const configPath = join(outputDir, 'node.cnf')
    this.writeFile(configPath, nodeConfig)
  }

  /**
   * CA Config 作成
   * @param outputDir 出力ディレクトリ
   * @param caName CA名
   * @param caPriKeyPath 秘密鍵ファイルパス
   */
  private createCaConfig(outputDir: string, caName: string, caPriKeyPath: string) {
    console.log('CA Config 作成')

    const privateKeyPathEsc = caPriKeyPath.replaceAll('\\', '\\\\')

    const caConfig = `[ca]
default_ca = CA_default

[CA_default]
new_certs_dir = ./new_certs

database = index.txt
serial   = serial.dat
private_key = ${privateKeyPathEsc}
certificate = ca.crt.pem
policy = policy_catapult

[policy_catapult]
commonName = supplied

[req]
prompt = no
distinguished_name = dn

[dn]
CN = ${caName}
`
    const configPath = join(outputDir, 'ca.cnf')
    this.writeFile(configPath, caConfig)

    const indexPath = join(outputDir, 'index.txt')
    this.writeFile(indexPath, '')

    const newCertsDirPath = join(outputDir, 'new_certs')
    this.makeDir(newCertsDirPath)
  }

  /**
   * CA証明書作成
   * @param outputDir 出力ディレクトリ
   * @param privatekeyPath 秘密鍵ファイルパス
   * @param days 有効日数
   */
  private createCaCertificate(outputDir: string, privatekeyPath: string, days: number = 7300) {
    console.log('CA証明書作成')
    execSync(
      `openssl req ` +
        `-config ca.cnf ` +
        `-keyform PEM ` +
        `-key ${privatekeyPath} ` +
        `-new ` +
        `-x509 ` +
        `-days ${days} ` +
        `-out ca.crt.pem`,
      {
        cwd: outputDir,
      }
    )
  }

  /**
   * ノードCSR作成
   * @param outputDir 出力ディレクトリ
   * @param priKeyPath 秘密鍵
   */
  private createNodeCsr(outputDir: string, priKeyPath: string) {
    console.log('ノードCSR作成')
    execSync(`openssl req -config node.cnf -key ${priKeyPath} -new -out node.csr.pem`, {
      cwd: outputDir,
    })
  }

  /**
   * 署名
   * @param outputDir 出力ディレクトリ
   * @param days 有効日数
   */
  private signingCertificate(outputDir: string, days: number = 375) {
    console.log('Node証明書署名')
    execSync('openssl rand -out ./serial.dat -hex 19', {
      cwd: outputDir,
    })
    execSync(
      `openssl ca ` +
        `-config ca.cnf ` +
        `-days ${days} ` +
        `-notext ` +
        `-batch ` +
        `-in node.csr.pem ` +
        `-out node.crt.pem`,
      {
        cwd: outputDir,
      }
    )
  }

  /**
   * 証明書失効
   * @param workDir 作業ディレクトリ
   */
  private revokeCertificate(workDir: string) {
    console.log('Node証明書失効')
    execSync(`openssl ca -config ca.cnf -revoke node.crt.pem`, {
      cwd: workDir,
    })
  }

  /**
   * 公開鍵生成
   * @param privatekeyPath 秘密鍵ファイルパス
   * @param publickeyPath 公開鍵ファイルパス
   */
  private generatePublicKey(privatekeyPath: string, publickeyPath: string) {
    console.log(`公開鍵作成`)
    execSync(`openssl pkey ` + `-in ${privatekeyPath} ` + `-out ${publickeyPath} ` + `-pubout`)
  }

  /**
   * 秘密鍵生成
   * @param outputDir 出力ディレクトリ
   * @param privatekeyFilePath 秘密鍵ファイル名
   */
  private generatePrivateKey(privatekeyFilePath: string) {
    console.log(`秘密鍵生成`)
    execSync(`openssl genpkey ` + `-algorithm ed25519 ` + `-outform PEM ` + `-out ${privatekeyFilePath}`)
    // パーミッション変更
    chmodSync(privatekeyFilePath, 0o600)
  }

  /**
   * OpenSSLバージョンチェック
   */
  private checkVersionOpenSsl() {
    let versionOutput = ''
    try {
      const versionOutputBuffer = execSync('openssl version')
      versionOutput = versionOutputBuffer.toString()
    } catch {
      throw Error('openssl execution failure')
    }
    const regex = /^OpenSSL +([^ ]*) /
    const match = versionOutput.match(regex)
    const reqVer = '3.0.2'
    if (match === null || match[1] <= reqVer) {
      // console.log('Windowsの場合 -> https://slproweb.com/products/Win32OpenSSL.html')
      throw Error(`requires openssl version >=${reqVer}`)
    }
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
   * ディレクトリの作成
   * @param dirPath ディレクトリパス
   */
  private makeDir(dirPath: string) {
    try {
      mkdirSync(dirPath, { recursive: true })
    } catch {
      throw Error(`ディレクトリの作成に失敗しました。: ${dirPath}`)
    }
  }
}
