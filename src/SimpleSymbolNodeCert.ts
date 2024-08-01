import { execSync } from 'child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join, resolve } from 'path'

export class SimpleSymbolNodeCert {
  /**
   * Symbolノード証明書発行
   * @param certDir 証明書出力ディレクトリ
   * @param caName CA名
   * @param nodeName ノード名
   * @param days 有効日数
   * @param isForce 上書出力
   */
  public generate(
    certDir: string = './cert',
    caName: string = 'my cool CA',
    nodeName: string = 'my cool node name',
    days: number = 375,
    isForce: boolean = false
  ) {
    const outputDir = resolve(certDir)

    // OpenSSLバージョンチェック
    this.checkVersionOpenSsl()

    // 出力ディレクトリ作成
    if (existsSync(outputDir)) {
      if (isForce) {
        rmSync(outputDir, { recursive: true })
      } else {
        throw Error('output directory already exists')
      }
    }
    mkdirSync(outputDir, { recursive: true })

    console.log(`  CA common name: ${caName}`)
    console.log(`Node common name: ${nodeName}`)

    // 秘密鍵生成
    const caPriKeyFileName = 'ca.key.pem'
    this.generatePrivateKey(outputDir, caPriKeyFileName)
    const nodePriKeyFileName = 'node.key.pem'
    this.generatePrivateKey(outputDir, nodePriKeyFileName)

    // 設定ファイル作成
    const caPriKeyPath = join(outputDir, caPriKeyFileName)
    this.createCaConfig(outputDir, caName, caPriKeyPath)
    this.createNodeConfig(outputDir, nodeName)

    // 公開鍵生成
    const pubKeyFileName = 'ca.pubkey.pem'
    this.generatePublicKey(outputDir, caPriKeyPath, pubKeyFileName)

    // 証明書作成
    this.createCaCertificate(outputDir, caPriKeyPath, days)
    this.createNodeCsr(outputDir, nodePriKeyFileName)
    this.signingCertificate(outputDir, days)
    // 証明書連結
    this.createSymbolNodeCert(outputDir)
  }

  /**
   * Symbolノード証明書の期限を更新する
   * @param certDir 証明書ディレクトリ
   */
  public renew(certDir: string = './cert') {
    const inputDir = resolve(certDir)

    const caPriKeyFileName = 'ca.key.pem'
    const caPriKeyPath = join(inputDir, caPriKeyFileName)
    const nodePriKeyFileName = 'node.key.pem'

    // 古いデータベース削除
    this.revokeCertificate(inputDir)

    // 証明書作成
    this.createCaCertificate(inputDir, caPriKeyPath, 7300)
    this.createNodeCsr(inputDir, nodePriKeyFileName)
    this.signingCertificate(inputDir, 3750)

    this.createSymbolNodeCert(inputDir)
  }

  /**
   * Symbolノード証明書の期限と公開鍵表示
   * @param certDir 証明書ディレクトリ
   */
  public info(certDir: string = './cert') {
    const inputDir = resolve(certDir)

    let certInfo
    try {
      certInfo = execSync(
        `openssl crl2pkcs7 -nocrl -certfile node.full.crt.pem` +
          ` | openssl pkcs7 -print_certs -text -noout`,
        {
          cwd: inputDir,
        }
      )
    } catch {
      throw Error('openssl execution failure')
    }

    // 開始日
    const startDates: Date[] = []
    const startDateMatches = certInfo.toString().matchAll(/Not Before: (.*)/g)
    for (const match of startDateMatches) {
      startDates.push(new Date(match[1]))
    }
    // 終了日
    const endDates: Date[] = []
    const endDateMatches = certInfo.toString().matchAll(/Not After : (.*)/g)
    for (const match of endDateMatches) {
      endDates.push(new Date(match[1]))
    }
    // 公開鍵
    const publicKeys: string[] = []
    const publicKeyMatches = certInfo
      .toString()
      .matchAll(
        /pub:[\r\n|\n|\r]\s+(.*)[\r\n|\n|\r]\s+(.*)[\r\n|\n|\r]\s+(.*)/g
      )
    for (const match of publicKeyMatches) {
      let pubKey = match[1] + match[2] + match[3]
      pubKey = pubKey.replaceAll(':', '')
      publicKeys.push(pubKey.toUpperCase())
    }

    console.log(`==================================================`)
    console.log(`CA Cert:`)
    console.log(`  Start Date: ${startDates[0]}`)
    console.log(`    End Date: ${endDates[0]}`)
    console.log(`  Public Key: ${publicKeys[0]}`)
    console.log(`Node Cert:`)
    console.log(`  Start Date: ${startDates[1]}`)
    console.log(`    End Date: ${endDates[1]}`)
    console.log(`  Public Key: ${publicKeys[1]}`)
    console.log(`==================================================`)
  }

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
    const nodeConfig = `[req]
prompt = no
distinguished_name = dn
[dn]
CN = ${nodeName}
`
    const configPath = join(outputDir, 'node.cnf')
    writeFileSync(configPath, nodeConfig)
  }

  /**
   * CA Config 作成
   * @param outputDir 出力ディレクトリ
   * @param caName CA名
   * @param caPriKeyPath 秘密鍵ファイルパス
   */
  private createCaConfig(
    outputDir: string,
    caName: string,
    caPriKeyPath: string
  ) {
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
    writeFileSync(configPath, caConfig)

    const indexPath = join(outputDir, 'index.txt')
    writeFileSync(indexPath, '')

    const newCertsDirPath = join(outputDir, 'new_certs')
    mkdirSync(newCertsDirPath, { recursive: true })
  }

  /**
   * CA証明書作成
   * @param outputDir 出力ディレクトリ
   * @param priKeyPath 秘密鍵
   * @param days 有効日数
   */
  private createCaCertificate(
    outputDir: string,
    priKeyPath: string,
    days: number = 7300
  ) {
    console.log('creating CA certificate')
    try {
      execSync(
        `openssl req -config ca.cnf -keyform PEM -key ${priKeyPath} -new -x509 -days ${days} -out ca.crt.pem`,
        {
          cwd: outputDir,
        }
      )
    } catch {
      throw Error('openssl execution failure')
    }
  }

  /**
   * ノードCSR作成
   * @param outputDir 出力ディレクトリ
   * @param priKeyPath 秘密鍵
   */
  private createNodeCsr(outputDir: string, priKeyPath: string) {
    console.log('preparing node CSR')
    try {
      execSync(
        'openssl req ' +
          '-config node.cnf ' +
          `-key ${priKeyPath} ` +
          '-new ' +
          '-out node.csr.pem ',
        {
          cwd: outputDir,
        }
      )
    } catch {
      throw Error('openssl execution failure')
    }
  }

  /**
   * 署名
   * @param outputDir 出力ディレクトリ
   * @param days 有効日数
   */
  private signingCertificate(outputDir: string, days: number = 375) {
    console.log('signing node certificate')
    try {
      execSync('openssl rand -out ./serial.dat -hex 19', {
        cwd: outputDir,
      })
      execSync(
        `openssl ca -config ca.cnf -days ${days} -notext -batch ` +
          '-in node.csr.pem ' +
          '-out node.crt.pem',
        {
          cwd: outputDir,
        }
      )
    } catch (e) {
      console.error(e)
      throw Error('openssl execution failure')
    }
  }

  /**
   * 証明書失効
   * @param workDir 作業ディレクトリ
   */
  private revokeCertificate(workDir: string) {
    console.log('revoke node certificate')
    try {
      execSync(`openssl ca -config ca.cnf -revoke node.crt.pem`, {
        cwd: workDir,
      })
    } catch (e) {
      console.error(e)
    }
  }

  /**
   * 公開鍵生成
   * @param outputDir 出力ディレクトリ
   * @param priKeyPath 秘密鍵ファイルパス
   * @param pubKeyFileName 公開鍵ファイル名
   */
  private generatePublicKey(
    outputDir: string,
    priKeyPath: string,
    pubKeyFileName: string
  ) {
    console.log(`creating ${pubKeyFileName}`)
    try {
      execSync(
        `openssl pkey -in ${priKeyPath} -out ${pubKeyFileName} -pubout`,
        {
          cwd: outputDir,
        }
      )
    } catch {
      throw Error('openssl execution failure')
    }
  }

  /**
   * 秘密鍵生成
   * @param outputDir 出力ディレクトリ
   * @param priKeyFileName 秘密鍵ファイル名
   */
  private generatePrivateKey(outputDir: string, priKeyFileName: string) {
    console.log(`creating ${priKeyFileName}`)
    try {
      execSync(
        `openssl genpkey -algorithm ed25519 -outform PEM -out ${priKeyFileName}`,
        { cwd: outputDir }
      )
    } catch {
      throw Error('openssl execution failure')
    }
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
    if (match === null || match[1] <= '1.1.1') {
      throw Error('requires openssl version >=1.1.1')
    }
  }
}
