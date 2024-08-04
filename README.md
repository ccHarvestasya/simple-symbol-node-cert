# Simple Symbol Node Cert

## 何ができる？

Symbol ノードのSSLソケット通信用の証明書を簡易生成できます。

## OpenSSLインストール

OpenSSL 3.2.1 以上が必要です。

## インストール

```sh
npm i simple-symbol-node-cert
```

## 使い方

### 証明書生成

```typescript
generate(certDirPath, caName, nodeName, caCertDays, nodeCertDays, isForce, privatekeysFilePath, passwd)
```

- **certDirPath**  
  証明書出力ディレクトリパス
- **caName**  
  CA名
- **nodeName**  
  Node名
- **caCertDays**  
  CA証明書有効日数
- **nodeCertDays**  
  Node証明書有効日数
- **isForce**  
  trueで証明書を上書き生成する
- **privatekeysFilePath**  
  生成した秘密鍵を暗号化して保存するファイルパス
- **passwd**  
  暗号化パスワード

### 証明書更新

```typescript
renwe(certDirPath, caCertDays, nodeCertDays, isForce, privatekeysFilePath, passwd)
```

- **certDirPath**  
  証明書出力ディレクトリパス
- **caCertDays**  
  CA証明書有効日数
- **nodeCertDays**  
  Node証明書有効日数
- **privatekeysFilePath**  
  生成した秘密鍵を暗号化して保存するファイルパス
- **passwd**  
  暗号化パスワード

### 証明書確認

```typescript
info(certDirPath)
```

- **certDirPath**  
  証明書出力ディレクトリパス
