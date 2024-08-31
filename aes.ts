/**
 * 將字串轉換為適當的 Uint8Array 資料
 * @param str 要轉換的字串
 * @returns 轉換後的 Uint8Array
 */
function stringToUint8Array(str: string): Uint8Array {
  const len = str.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; ++i) {
    bytes[i] = str.charCodeAt(i)
  }
  return bytes
}

/**
 * 將未編碼的原始密鑰轉換為 CryptoKey
 * @param key 原始密鑰字串
 * @returns 轉換後的 CryptoKey
 */
async function importKey(key: string): Promise<CryptoKey> {
  const keyBytes = stringToUint8Array(key.padStart(32, '0'))

  return await window.crypto.subtle.importKey(
    'raw', // 輸入的密鑰資料類型
    keyBytes,
    {
      name: 'AES-GCM'
    },
    true, // 是否可導出密鑰
    ['encrypt', 'decrypt'] // 密鑰的用途
  )
}

/**
 * 加密訊息並返回 Base64 字串
 * @param key 用於加密的密鑰字串
 * @param message 要加密的訊息字串
 * @returns 加密後的 Base64 字串
 */
export async function encryptMessage(key: string, message: string): Promise<string> {
  const importedKey = await importKey(key)

  const encoder = new TextEncoder()
  const data = encoder.encode(message)

  // 生成一個隨機的初始化向量 (IV)
  const iv = window.crypto.getRandomValues(new Uint8Array(12))

  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    importedKey,
    data
  )

  // 將 IV 與加密資料合併
  const encryptedArray = new Uint8Array(encrypted)
  const result = new Uint8Array(iv.byteLength + encryptedArray.byteLength)
  result.set(iv, 0)
  result.set(encryptedArray, iv.byteLength)

  // 返回 Base64 編碼的結果
  return btoa(String.fromCharCode(...result))
}

/**
 * 解密 Base64 字串並返回明文
 * @param key 用於解密的密鑰字串
 * @param encryptedMessage 要解密的 Base64 字串
 * @returns 解密後的明文字串
 */
export async function decryptMessage(key: string, encryptedMessage: string): Promise<string> {
  const importedKey = await importKey(key)

  // 將 Base64 字串轉換為 Uint8Array
  const encryptedBytes = new Uint8Array(
    atob(encryptedMessage)
      .split('')
      .map((c) => c.charCodeAt(0))
  )

  // 提取初始化向量（IV）和加密資料
  const iv = encryptedBytes.slice(0, 12)
  const data = encryptedBytes.slice(12)

  // 解密資料
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    importedKey,
    data
  )

  // 將解密後的資料轉換為字串並返回
  const decoder = new TextDecoder()
  return decoder.decode(decrypted)
}
