export type PrivatekeysYaml = {
  main?: {
    privateKey: string
    publicKey?: string
  }
  transport?: {
    privateKey: string
    publicKey?: string
  }
}
