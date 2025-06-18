/*
*
* NJS Auth JWT
*   
* Copyright(c) 2025 Igor Potapov (i.n.potapov@yandex.ru)
* MIT Licensed
*
* Поддерживаемые алгоритмы JWT-токенов: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
*
* Ожидает токен только как аргумент "token" в строке запроса.
* Токен в заголовке Authorization не поддерживается.
*
* Алгоритм валидации:
* 1) Проверка формата токена
* 2) Проверка алгоритма токена
* 3) Проверка срока годности exp и nbf
* 4) Проверка подписи токена
* 5) Ключ проверки подписи загружается с диска при первом вызове и помещается в кэш зону Nginx. 
*    При последующих вызовах ключ берется из кэш зоны Nginx (до истечения установленного таймаута или перезагрузки Nginx)
* 6) В случае успешной валидации перенаправляет запрос в локейшн, указанный в переменной $jwt_go_to_location
*    В случае неудачной валидации сразу возвращает клиенту статус "401 Authorization Required"
*
*/



// импорты
import fs from 'fs'; // для доступа к файлам ключей
var Crypto = require('crypto'); //важно !!! в имени переменной первый символ в верхнем регистре "Crypto" (т.к. Crypto и crypto это разные объекты и оба используются в данном скрипте)
// crypto - объект реализующий Web Crypto API и доступный по умлочанию без импорта. Используется для проверки подписи токена
// Crypto - node.js-like модуль импортируем вручную. Используется для получения md5 хэша.




// Точка входа. Основная функция, принимающая объект запроса (r).

function jwt_validate(r) {

    //берем токен из аргумента запроса
    var token = r.args.token;

    // берем значения переменных из Location
    let publicKeyFile = r.variables.jwt_public_key_file;	// полный путь к файлу ключу шифрования токена
    let validateExp = r.variables.jwt_validate_exp || "no";	// необходимость валидации срока действия токена
    let gotoloc = r.variables.jwt_go_to_location;		    // в какой локейшн переходить в случае успешной валидации токена

    // Пытаемся валидировать
    try {
        validateJWT(token, publicKeyFile, validateExp)
        .then(isValid => {
            if(isValid)
            {
                r.internalRedirect(gotoloc);   // переходим в указанный локейшн
            }
            else
            {
                r.return(401); // возвращаем 401 Authorization Required
            }
            })
            .catch(err => {
            r.return(401); // возвращаем 401 Authorization Required
                console.error("Error:", err.message);
            });

        } catch (e) {   // если при расшифровке произошла ошибка значит токен не валидный

          r.return(401); // возвращаем 401 Authorization Required

        }
}






// Генерация MD5-хэша на основе пути к файлу (необходимо для формирования уникального ID для pem-ключа в кэше Nginx shared zone)
function getMd5(filePath) {
    const hash = Crypto.createHash('md5').update(filePath).digest('hex');
    return hash;
}






// загрузка публичного ключа из кэша или файла

async function loadPublicKey(filePath) {

    // Генерим md5 хэш на основе пути к файлу ключа
    const keyHash = getMd5(filePath);
    // Формируем идертификатор ключа для кэша
    const cacheKey = 'jwt_pub_key_' + keyHash;  // Например: "jwt_pub_key_a1b2c3d4..."

    // Пытаемся получить ключ из кеша с полученным идентификатором
    let publicKeyPem = ngx.shared.jwt_keys.get(cacheKey);

    // Если в кэше есть ключ то возвращаем его и прерываем функцию
    if (publicKeyPem) {return publicKeyPem;}

    // если в кэше нет ключа то берем из файла

    try {
            // Читаем ключ из файла
            publicKeyPem = fs.readFileSync(filePath, 'utf8');

            // Сохраняем в кэш
            ngx.shared.jwt_keys.set(cacheKey, publicKeyPem);

            return publicKeyPem;

        } catch (err) {
        throw new Error(`Failed to load public key from file: ${err.message}`);
        }
}






// Проверка срока действия токена (exp и nbf)
function checkTokenExpiration(payload, validateExp) {

    if (validateExp !== "yes") return true; // Пропускаем проверку, если не требуется

    const now = Math.floor(Date.now() / 1000); // Текущее время в секундах

    // Проверка существования exp
    if (!payload.exp) {
        throw new Error("Token has no 'exp' claim");
    }

    // Проверка даты exp
    if (payload.exp < now) {
        throw new Error("Token expired");
    }

    // Проверка "not before" (если поле есть)
    if (payload.nbf && payload.nbf > now) {
        throw new Error("Token is not yet valid (nbf)");
    }

    return true;
}





async function validateJWT(token, publicKeyFile, validateExp) {

    // загружаем публичный ключ (из кэша или файла)
    const publicKeyPem = await loadPublicKey(publicKeyFile);

    // разбиваем токен на части
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    // Берем каждую часть в отдельную переменную
    const headerB64 = parts[0];
    const payloadB64 = parts[1];
    const signatureB64 = parts[2];

    // извлекаем значение alg из хэдера токена
    const headerStr = Buffer.from(headerB64, 'base64').toString();
    const header = JSON.parse(headerStr);
    const alg = header.alg;
    if (!alg) throw new Error("JWT header missing 'alg' field");


    // Парсим payload токена
    const payloadStr = Buffer.from(payloadB64, 'base64url').toString();
    const payload = JSON.parse(payloadStr);


    // Проверяем срок действия токена exp и nbf (если требуется)
    checkTokenExpiration(payload, validateExp);


    // Определяем параметры алгоритма с учетом кривых для ECDSA
    const algorithmParams = {
        // Симметричные алгоритмы (HMAC)
        HS256: { name: "HMAC", hash: "SHA-256" },
        HS384: { name: "HMAC", hash: "SHA-384" },
        HS512: { name: "HMAC", hash: "SHA-512" },
	// Асимметричные алгоритмы RS
        RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
        RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
	// Асимметричные алгоритмы ES        
	ES256: { 
            name: "ECDSA",
            hash: "SHA-256",
            namedCurve: "P-256"  // Кривая для ES256
        },
        ES384: { 
            name: "ECDSA",
            hash: "SHA-384",
            namedCurve: "P-384"  // Кривая для ES384
        },
        ES512: { 
            name: "ECDSA",
            hash: "SHA-512",
            namedCurve: "P-521"  // Кривая для ES512
        }
    };

    const verifyAlgorithm = algorithmParams[alg];
    if (!verifyAlgorithm) throw new Error(`Unsupported JWT algorithm: ${alg}`);

    const dataToVerify = headerB64 + '.' + payloadB64;
    const signature = Buffer.from(signatureB64, 'base64url');
    
    

    
    // Разделяем логику для HMAC и RSA/ECDSA
     if (alg.toUpperCase().substring(0, 2) === 'HS') {
        // HMAC-алгоритмы     

	// Ключ для HMAC должен быть одной строкой - удаляем переводы строк        
	let publicKeyHmac = publicKeyPem.replace(/\r?\n|\r/g, '').trim();
        var publicKey = await crypto.subtle.importKey(
            'raw',
            Buffer.from(publicKeyHmac),
            verifyAlgorithm,
            false,
            ['verify']
        );
    } else {
      
        // RSA/ECDSA алгоритмы

	// Ключ для RSA/ECDSA берем как есть в формате pem, но чуть далее конвертируем буфер
	let publicKeyRsEs = publicKeyPem;
        var publicKey = await crypto.subtle.importKey(
            "spki",
            pemToArrayBuffer(publicKeyRsEs),
            verifyAlgorithm,
            false,
            ["verify"]
        );
    }


    // проверяем подпись токена (возвращаем true/false)
    return await crypto.subtle.verify(
        verifyAlgorithm,
        publicKey,
        signature,
        Buffer.from(dataToVerify)
    );

}




// Вспомогательная функция: конвертирует PEM в ArrayBuffer
function pemToArrayBuffer(pem) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem
        .replace(pemHeader, "")
        .replace(pemFooter, "")
        .replace(/\s+/g, ""); // Удаляем все пробелы и переводы строк
    return Buffer.from(pemContents, 'base64');
}



// Экспорт
export default {jwt_validate};
