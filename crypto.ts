import crypto, { CipherGCM, DecipherGCM } from 'crypto';
import { webcrypto as OqsKem } from 'crypto';
import oqs from "node-oqs";

interface ICryptoConfig {
  ivLength: number;
  saltLength: number;
  keyAlgorithm: string;
  encryptionAlgorithm: string;
}

const QUANT_CONFIG: ICryptoConfig = {
  ivLength: 100, // стандартная длина для AES-GCM
  saltLength: 100, // достаточная длина соли
  keyAlgorithm: 'sha3-256', // для квантовой устойчивости (решёточные алгоритмы)
  encryptionAlgorithm: 'aes-256-gcm', // используется AES-GCM; для реальной квантовой защиты замените на решёточный алгоритм
};

type ICryptoKey = string[];

/**
 * Функция для генерации «решёточного» ключа.
 * Сначала используется PBKDF2 с увеличенным количеством итераций,
 * затем полученный ключ дополнительно хэшируется с помощью SHA3-256.
 */
const deriveLatticeKey = async (keys: ICryptoKey, salt: Buffer): Promise<Buffer> => {
  if (!keys || keys.length === 0 || keys.some(key => typeof key !== 'string' || !key.trim())) {
    throw new Error('Необходимо предоставить корректные непустые ключи.');
  }

  // Используем PBKDF2 с очень высоким количеством итераций для повышения безопасности
  const baseKey: Buffer = await new Promise((resolve, reject) => {
    crypto.pbkdf2(
      keys.join(''),
      salt,
      620000, // повышенное количество итераций для усиленной защиты
      55,
      'sha256',
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve(derivedKey);
      }
    );
  });

  // Дополнительная обработка – хэширование для имитации решёточной схемы
  const latticeKey = crypto.createHash('sha3-256').update(baseKey).digest();
  return latticeKey;
};

/**
 * Проверка, находится ли строка в формате Base64.
 */
const isBase64 = (data: string): boolean => {
  if (typeof data !== 'string') return false;
  try {
    return Buffer.from(data, 'base64').toString('base64') === data;
  } catch {
    return false;
  }
};

/*
  Реализация псевдо-решёточного шифрования для защиты симметричного ключа.
  Здесь мы реализуем простейший алгоритм на основе сети Фейстеля, который используется для
  «обертывания» (encapsulation) ключа AES. Это демонстрационная реализация и не гарантирует
  реальной квантовой защиты.
*/

/**
 * Функция шифрования блока (32 байта) с использованием сети Фейстеля.
 * Используется массив раундовых ключей, размер блока делится на две половины по 16 байт.
 */
function feistelEncrypt(block: Buffer, roundKeys: Buffer[]): Buffer {
  const blockSize = block.length; // Ожидается 32 байта
  const half = blockSize / 2;
  let L = Buffer.from(block.slice(0, half));
  let R = Buffer.from(block.slice(half));

  for (let i = 0; i < roundKeys.length; i++) {
    // Функция раунда: берем SHA3-256 от (R + раундовый ключ) и используем первые 16 байт
    const f = crypto.createHash('sha3-256')
      .update(Buffer.concat([R, roundKeys[i]]))
      .digest()
      .slice(0, half);
    const newR = Buffer.alloc(half);
    for (let j = 0; j < half; j++) {
      newR[j] = L[j] ^ f[j];
    }
    L = R;
    R = newR;
  }
  // Финальный обмен местами для симметричного преобразования
  return Buffer.concat([R, L]);
}

/**
 * Функция дешифрования блока (32 байта) с использованием обратного порядка раундов.
 */
function feistelDecrypt(block: Buffer, roundKeys: Buffer[]): Buffer {
  const blockSize = block.length;
  const half = blockSize / 2;
  let R = Buffer.from(block.slice(0, half));
  let L = Buffer.from(block.slice(half));

  for (let i = roundKeys.length - 1; i >= 0; i--) {
    const f = crypto.createHash('sha3-256')
      .update(Buffer.concat([L, roundKeys[i]]))
      .digest()
      .slice(0, half);
    const newL = Buffer.alloc(half);
    for (let j = 0; j < half; j++) {
      newL[j] = R[j] ^ f[j];
    }
    R = L;
    L = newL;
  }
  return Buffer.concat([L, R]);
}

/**
 * Функция «решёточного» шифрования симметричного ключа.
 * Реализуется на основе сети Фейстеля с 16 раундами.
 */
function latticeEncryptKey(sessionKey: Buffer, latticeKey: Buffer): Buffer {
  // Гарантируем, что sessionKey имеет длину 32 байта
  let key = sessionKey;
  if (sessionKey.length !== 32) {
    key = Buffer.alloc(32);
    sessionKey.copy(key, 0, 0, Math.min(sessionKey.length, 32));
  }
  const rounds = 16;
  const roundKeys: Buffer[] = [];
  for (let i = 0; i < rounds; i++) {
    // Раундовый ключ формируется на основе latticeKey и номера раунда
    const roundKey = crypto.createHmac('sha3-256', latticeKey)
      .update(Buffer.from([i]))
      .digest();
    roundKeys.push(roundKey);
  }
  return feistelEncrypt(key, roundKeys);
}

/**
 * Функция дешифрования симметричного ключа, зашифрованного с помощью latticeEncryptKey.
 */
function latticeDecryptKey(encryptedKey: Buffer, latticeKey: Buffer): Buffer {
  const rounds = 16;
  const roundKeys: Buffer[] = [];
  for (let i = 0; i < rounds; i++) {
    const roundKey = crypto.createHmac('sha3-256', latticeKey)
      .update(Buffer.from([i]))
      .digest();
    roundKeys.push(roundKey);
  }
  return feistelDecrypt(encryptedKey, roundKeys);
}

/**
 * Функция квантового (решёточного) шифрования данных.
 * Здесь реализован гибридный подход:
 * 1. Генерируется случайный симметричный sessionKey для AES-256-GCM.
 * 2. Данные шифруются AES-256-GCM с использованием sessionKey.
 * 3. Сам sessionKey завуёртывается (encapsulate) с помощью псевдо-решёточного шифрования,
 *    где для его защиты используется ключ, полученный от deriveLatticeKey.
 * В результирующем сообщении последовательно содержатся: соль, IV, тег аутентификации,
 * зашифрованный sessionKey и зашифрованный контент.
 */
export const quantEncryptedData = async (data: any, keys: ICryptoKey): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('Данные для шифрования отсутствуют.');
  }

  const salt = crypto.randomBytes(QUANT_CONFIG.saltLength);
  const latticeKey = await deriveLatticeKey(keys, salt);
  // Генерация случайного симметричного ключа (sessionKey) для AES
  const sessionKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(QUANT_CONFIG.ivLength);

  const cipher = crypto.createCipheriv(QUANT_CONFIG.encryptionAlgorithm, sessionKey, iv) as CipherGCM;
  try {
    const serializedData = JSON.stringify(data);
    const encryptedContent = Buffer.concat([
      cipher.update(serializedData, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // Шифрование (обёртывание) sessionKey с использованием псевдо-решёточного алгоритма
    const encryptedSessionKey = latticeEncryptKey(sessionKey, latticeKey);

    // Формируем итоговое сообщение:
    // salt | iv | authTag (16 байт) | зашифрованный sessionKey (32 байта) | encryptedContent
    return Buffer.concat([
      salt,
      iv,
      authTag,
      encryptedSessionKey,
      encryptedContent
    ]).toString('base64');
  } catch (error) {
    throw new Error('Не удалось зашифровать данные. Проверьте входные данные и ключи.');
  }
};

/**
 * Функция квантового (решёточного) дешифрования данных.
 * Производится обратный процесс:
 * 1. Извлекаются компоненты шифротекста: соль, IV, authTag, зашифрованный sessionKey и зашифрованный контент.
 * 2. С помощью deriveLatticeKey и latticeDecryptKey восстанавливается sessionKey.
 * 3. С использованием sessionKey данные дешифруются AES-256-GCM.
 */
export const quantDecryptedData = async (encryptedData: any, keys: ICryptoKey): Promise<any> => {
  if (!encryptedData) {
    throw new Error('Данные для дешифрования отсутствуют или некорректны.');
  }

  if (typeof encryptedData !== 'string' || !isBase64(encryptedData)) {
    return encryptedData; // Если данные не в формате Base64, возвращаем как есть
  }

  const bufferData = Buffer.from(encryptedData, 'base64');

  const salt = bufferData.slice(0, QUANT_CONFIG.saltLength);
  const ivStart = QUANT_CONFIG.saltLength;
  const ivEnd = ivStart + QUANT_CONFIG.ivLength;
  const iv = bufferData.slice(ivStart, ivEnd);
  const authTagStart = ivEnd;
  const authTagEnd = authTagStart + 16;
  const authTag = bufferData.slice(authTagStart, authTagEnd);
  const encryptedSessionKeyStart = authTagEnd;
  const encryptedSessionKeyEnd = encryptedSessionKeyStart + 32;
  const encryptedSessionKey = bufferData.slice(encryptedSessionKeyStart, encryptedSessionKeyEnd);
  const encryptedContent = bufferData.slice(encryptedSessionKeyEnd);

  const latticeKey = await deriveLatticeKey(keys, salt);
  // Дешифруем sessionKey с помощью псевдо-решёточного алгоритма
  const sessionKey = latticeDecryptKey(encryptedSessionKey, latticeKey);

  const decipher = crypto.createDecipheriv(QUANT_CONFIG.encryptionAlgorithm, sessionKey, iv) as DecipherGCM;
  decipher.setAuthTag(authTag);

  try {
    const decryptedContent = Buffer.concat([
      decipher.update(encryptedContent),
      decipher.final()
    ]);

    return JSON.parse(decryptedContent.toString('utf8'));
  } catch (error) {
    throw new Error('Не удалось расшифровать данные. Проверьте ключи или целостность данных.');
  }
};

/* ---------------------------------------------------------------------------
   Реализация демо-постквантового механизма защиты данных,
   использующего асимметричный ключевой обмен в виде KEM.
--------------------------------------------------------------------------- */

/**
 * Интерфейс для пары постквантовых ключей.
 */
interface IPQKeyPair {
  publicKey: Buffer;  // публичный ключ (32 байта)
  privateKey: Buffer; // приватный ключ (32 байта)
}

const PQC_ALGORITHM = 'Kyber512';
const IV_LENGTH = 12; // Рекомендуемая длина IV для AES-256-GCM

/**
 * Генерация пары постквантовых ключей с использованием node-oqs.
 *
 * Метод генерирует ключевую пару (publicKey и privateKey) на основе выбранного алгоритма,
 * например, Kyber512, который считается одним из самых мощных постквантовых решений.
 */
export const generatePostQuantumKeyPair = (): { publicKey: Buffer, privateKey: Buffer } => {
  const kem = new oqs.KEM(PQC_ALGORITHM);
  const { publicKey, secretKey } = kem.generateKeyPair(); // secretKey будем использовать как privateKey
  return { publicKey, privateKey: secretKey };
};

/**
 * Функция надежного шифрования данных с использованием постквантовой инкапсуляции ключа (KEM)
 * из библиотеки node-oqs и симметричного шифрования AES-256-GCM.
 *
 * Алгоритм работы:
 * 1. На основе публичного ключа получателя производится инкапсуляция: генерируется общий секрет и encapsulatedKey.
 * 2. Из общего секрета при помощи SHA-256 выводится 32-байтовый симметричный ключ.
 * 3. Данные шифруются алгоритмом AES-256-GCM с использованием симметричного ключа.
 * 4. Итоговое сообщение состоит из: encapsulatedKey | IV | authTag | зашифрованный контент.
 */
export const secureEncryptData = async (data: any, recipientPublicKey: Buffer): Promise<string> => {
  if (data === undefined || data === null) {
    throw new Error('Данные для шифрования отсутствуют.');
  }

  const serializedData = JSON.stringify(data);

  // Инициализируем KEM из node-oqs для выбранного алгоритма
  const kem = new oqs.KEM(PQC_ALGORITHM);

  // Инкапсуляция: генерируем общий секрет и encapsulatedKey на основе публичного ключа получателя
  const { sharedSecret, encapsulatedKey } = kem.encapsulate(recipientPublicKey);

  // Вывод симметричного ключа из общего секрета (32 байта)
  const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();

  // Генерируем стандартный IV (12 байт для AES-256-GCM)
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

  const encryptedContent = Buffer.concat([
    cipher.update(serializedData, 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  // Формируем итоговое сообщение: encapsulatedKey | IV | authTag | зашифрованный контент
  return Buffer.concat([encapsulatedKey, iv, authTag, encryptedContent]).toString('base64');
};

/**
 * Функция дешифрования данных, зашифрованных secureEncryptData.
 *
 * Алгоритм работы:
 * 1. Из итогового сообщения извлекаются encapsulatedKey, IV, authTag и зашифрованный контент.
 * 2. С использованием приватного ключа получателя выполняется декapsulation для получения общего секрета.
 * 3. Из полученного общего секрета выводится симметричный ключ посредством SHA-256.
 * 4. Зашифрованный контент дешифруется алгоритмом AES-256-GCM.
 */
export const secureDecryptData = async (encryptedData: any, recipientPrivateKey: Buffer): Promise<any> => {
  if (!encryptedData) {
    throw new Error('Данные для дешифрования отсутствуют или некорректны.');
  }
  if (typeof encryptedData !== 'string') {
    throw new Error('Неверный формат зашифрованных данных.');
  }

  const bufferData = Buffer.from(encryptedData, 'base64');

  // Инициализируем KEM для получения длины encapsulatedKey
  const kem = new oqs.KEM(PQC_ALGORITHM);
  const encapsulatedKeyLength = kem.getCiphertextLength();

  const encapsulatedKey = bufferData.slice(0, encapsulatedKeyLength);
  const iv = bufferData.slice(encapsulatedKeyLength, encapsulatedKeyLength + IV_LENGTH);
  const authTag = bufferData.slice(encapsulatedKeyLength + IV_LENGTH, encapsulatedKeyLength + IV_LENGTH + 16);
  const encryptedContent = bufferData.slice(encapsulatedKeyLength + IV_LENGTH + 16);

  // Декapsulation: восстанавливаем общий секрет с использованием приватного ключа
  const sharedSecret = kem.decapsulate(encapsulatedKey, recipientPrivateKey);
  const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();

  const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
  decipher.setAuthTag(authTag);

  const decryptedContent = Buffer.concat([
    decipher.update(encryptedContent),
    decipher.final()
  ]);

  return JSON.parse(decryptedContent.toString('utf8'));
};
