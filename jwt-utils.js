 // I used stackoverflow for a teeny tiny help  :)

 const crypto = require('crypto');

 // Converts string to base64url
 function base64url(input) { 
   return Buffer.from(input)
     .toString('base64')
     .replace(/=/g, '') 
     .replace(/\+/g, '-') 
     .replace(/\//g, '_'); 
 }
 
 // Decodes a base64url back to string
 function base64urlDecode(base64UrlString) { 
   base64UrlString = base64UrlString.replace(/-/g, '+').replace(/_/g, '/'); 
   while (base64UrlString.length % 4 !== 0) base64UrlString += '=';  
   return Buffer.from(base64UrlString, 'base64').toString('utf8'); 
 }
 

 function signJWT(payloadData, secretKey, expirationTimeInSeconds = 36) {
   const header = {
     alg: "HS256", 
     typ: "JWT"   
   };
 

   const expirationTime = Math.floor(Date.now() / 1000) + expirationTimeInSeconds;
   const payloadWithExpiration = { ...payloadData, exp: expirationTime };
   const encodedHeader = base64url(JSON.stringify(header));
   const encodedPayload = base64url(JSON.stringify(payloadWithExpiration));
  
   const dataToSign = [encodedHeader, encodedPayload].join('.');
 
   const signature = base64url(crypto
     .createHmac('sha256', secretKey)
     .update(dataToSign)
     .digest('base64')); 
 
  
   return [encodedHeader, encodedPayload, signature].join('.');
 }
 

 function verifyJWT(token, secretKey) {
   const [encodedHeader, encodedPayload, receivedSignature] = token.split('.');
 

   if (!encodedHeader || !encodedPayload || !receivedSignature) {
     throw new Error('Invalid token format');
   }
 

   const dataToSign = encodedHeader + '.' + encodedPayload;
 
   
   const expectedSignature = crypto
     .createHmac('sha256', secretKey)
     .update(dataToSign)
     .digest('base64') 
     .replace(/=/g, '')  
     .replace(/\+/g, '-') 
     .replace(/\//g, '_'); 
 
   if (expectedSignature !== receivedSignature) {
     throw new Error('Invalid signature');
   }
   const payloadJson = base64urlDecode(encodedPayload);
   const payload = JSON.parse(payloadJson);
   const currentTime = Math.floor(Date.now() / 1000);
   if (payload.exp && payload.exp < currentTime) {
     throw new Error('Token has expired');
   }
   return payload;
 }
 
 module.exports = { signJWT, verifyJWT };
 
  