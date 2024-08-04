export type PrivatekeysYaml = {
  main?: {
    testnetAddress?: string
    mainnetAddress?: string
    privateKey: string
    publicKey?: string
  }
  transport?: {
    testnetAddress?: string
    mainnetAddress?: string
    privateKey: string
    publicKey?: string
  }
}
