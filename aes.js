// 将字符串转换为适当的 Uint8Array 数据
function stringToUint8Array(str) {
  const len = str.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; ++i) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

// 将未编码的原始密钥转换为 CryptoKey
async function importKey(key) {
  const keyBytes = stringToUint8Array(key.padStart(32, "0"));

  return await window.crypto.subtle.importKey(
    "raw", // 输入的密钥数据类型
    keyBytes,
    {
      name: "AES-GCM",
    },
    true, // 是否可导出密钥
    ["encrypt", "decrypt"] // 密钥的用途
  );
}

// 加密消息并返回 Base64 字符串
async function encryptMessage(key, message) {
  const importedKey = await importKey(key);

  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  // 生成一个随机的初始化向量 (IV)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    importedKey,
    data
  );

  // 将 IV 与加密数据合并
  const encryptedArray = new Uint8Array(encrypted);
  const result = new Uint8Array(iv.byteLength + encryptedArray.byteLength);
  result.set(iv, 0);
  result.set(encryptedArray, iv.byteLength);

  // 返回 Base64 编码的结果
  return btoa(String.fromCharCode.apply(null, result));
}

// 解密 Base64 字符串并返回明文
async function decryptMessage(key, encryptedMessage) {
  const importedKey = await importKey(key);

  // 将 Base64 字符串转换为 Uint8Array
  const encryptedBytes = new Uint8Array(
    atob(encryptedMessage)
      .split("")
      .map(function (c) {
        return c.charCodeAt(0);
      })
  );

  // 提取初始化向量（IV）和加密数据
  const iv = encryptedBytes.slice(0, 12);
  const data = encryptedBytes.slice(12);

  // 解密数据
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    importedKey,
    data
  );

  // 将解密后的数据转换为字符串并返回
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}
