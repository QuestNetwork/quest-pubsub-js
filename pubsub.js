const axios = require('axios');
const CryptoJS = require('crypto-js')
const { generateKeyPairSync } = require('crypto');
const { v4: uuidv4 } = require('uuid');

function isInArray(value, array) {
  return array.indexOf(value) > -1;
}

const v3only = require('./swarm.json').v3only;
const combined = require('./swarm.json').combined;
const DEVMODE = false;
const secretKeyV2 = require('./swarm.json').reCaptchaRemote.secretKeyV2;
const secretKeyV3 = require('./swarm.json').reCaptchaRemote.secretKeyV3;

export class PubSub {


  constructor(channel = "all") {
    //in the future only handle one channel per instanciated class
    this.ipfsCID = "";
    this.subs = {};
    this.channelParticipantList = {};
    this.channelKeyChain = {};
  }

  createChannel(channelInput){
    //generate keypair
    let channelKeyChain = this.generateChannelKeyChain();
    let democracy = "rep";
    let channel = channelInput+"-|-"+channelKeyChain['channelPubKey']+"-|-"+democracy;
    this.setChannelKeyChain(channel, channelKeyChain);
    this.setChannelParticipantList(channel, {cList: channelKeyChain['channelPubKey'], pList: channelKeyChain['pubKey']});
    return channel;
  }

  ownerCheck(channel, pubKey){
    return ((channel.indexOf(pubKey) > -1) ? true : false);
  }

  parseParticipantList(plist){
    return plist.split(',');
  }
  isParticipant(list, key){
    return ((list.indexOf(key) > -1) ? true : false);
  }
  getChannelParticipantList(channel = 'all'){
    if(channel == 'all'){
      return this.channelParticipantList;
    }
    if(typeof(this.channelParticipantList[channel]['cList']) != 'undefined' && typeof(this.channelParticipantList[channel]['pList']) != 'undefined'){
      resolve(this.channelParticipantList[channel]);
    }
    throw('participants not saved');
  }
  setChannelParticipantList(participantList, channel = "all"){
    if(channel == 'all'){
      this.channelParticipantList = participantList;
    }
    else{
      this.channelParticipantList[channel] = participantList;
    }
  }
  addChannelParticipant(channel,channelPubKey, pubKey){
    this.channelParticipantList[channel][cList] += ","+channelPubKey;
    this.channelParticipantList[channel][pList] += ","+pubKey;
  }


  setChannelKeyChain(keychain, channel = "all"){
    if(channel == "all"){
        this.channelKeyChain = keychain;
    }
    else{
      this.channelKeyChain[channel] = keychain;
    }
  }

  getChannelKeyChain(channel = 'all'){
    if(channel == 'all'){
      return this.channelKeyChain;
    }
    return this.channelKeyChain[channel];
  }



  stringToArrayBuffer(string,format = 'utf8'){
  let encryptedSecretBuffer = string;

  let encryptedSecretBinaryString = Buffer.from(encryptedSecretBuffer, format).toString('binary');
  let encryptedSecretArrayBuffer = new Uint8Array(encryptedSecretBinaryString.length)
   for (var i = 0; i < encryptedSecretBinaryString.length; i++) {
     encryptedSecretArrayBuffer[i] = encryptedSecretBinaryString.charCodeAt(i)
   }
   return encryptedSecretArrayBuffer;
  }


   generateAesPassphrase(length) {
    length = length - 36;

     var result           = '';
     var characters       = 'abcdefghijklmnopqrstuvwxyz0123456789-!#?';
     var charactersLength = characters.length;
     for ( var i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
     }

     //combine with uuid
     result = uuidv4() + result;

     return result;
  }
  aesEncryptB64(b64, whistle = undefined){
    //string to array buffer
    let wordArray = CryptoJS.lib.WordArray.create(stringToArrayBuffer(b64,'base64'));
    CryptoJS.enc.parse(B64,CryptoJS.enc.base64);
    return this.aesEncryptWordArray(wordArray,whistle);
  }
  aesEncryptUtf8(utf8, whistle = undefined){
    //string to array buffer
    let wordArray = CryptoJS.lib.WordArray.create(stringToArrayBuffer(utf8,'utf8'));
    CryptoJS.enc.parse(B64,CryptoJS.enc.base64);
    return this.aesEncryptWordArray(wordArray,whistle);
  }
  aesEncryptWordArray(wordArray, whistle = undefined){
    let secret;
    if(typeof(whistle) == 'undefined'){
        secret = this.generateAesPassphrase(256);
    }
    else{
      secret = whistle;
    }

        console.log('encryption start...');

        // KEYS FROM SECRET
        var key = CryptoJS.enc.Utf8.parse(secret.slice(0,64));         // Key: Use a WordArray-object instead of a UTF8-string / NodeJS-buffer
        var iv = CryptoJS.enc.Utf8.parse(secret.substr(secret.length-16));
        // ENCRYPT
        let aesEncryptedB64 = CryptoJS.AES.encrypt(wordArray, key, {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7
        }).toString();


        // RESULT
        console.log(aesEncryptedB64);
        console.log('encryption complete!');

          return { secret, aesEncryptedB64}
  }
  aesDecryptB64(encryptedQuestFileB64, questFileKey, format = 'utf8'){
    let decryptedQuestFileWordArray;
    try{
      //aes decrypt this file
      let key = CryptoJS.enc.Utf8.parse(questFileKey.slice(0,64));         // Key: Use a WordArray-object instead of a UTF8-string / NodeJS-buffer
      let iv = CryptoJS.enc.Utf8.parse(questFileKey.substr(questFileKey.length-16));
      decryptedQuestFileWordArray = CryptoJS.AES.decrypt(encryptedQuestFileB64, key, {
         iv: iv,
         mode: CryptoJS.mode.CBC,
         padding: CryptoJS.pad.Pkcs7
      });
      if(decryptedQuestFileWordArray['sigBytes'] < 1){
        throw('bad key! tell user!');
      }
    }
    catch(error){
      console.log(error);
      throw('decryption failed');
    }
    if(format == 'hex'){
      return decryptedQuestFileWordArray.toString(CryptoJS.enc.Hex);
    }
    else if(format == 'base64'){
      return decryptedQuestFileWordArray.toString(CryptoJS.enc.Base64);
    }
    else if(format == 'utf8'){
      decryptedQuestFileWordArray.toString(CryptoJS.enc.Hex);
      return Buffer.from(decryptedQuestFileWordArray,'hex').toString('utf8');
    }
  }
  generateChannelKeyChain(){
    let keyPair = window.crypto.subtle.generateKey({
      name: 'ECDSA',
      namedCurve: 'P-512'
    },
    true,
    ["sign","verify"]);

    let channelPubKey = keyPair.publicKey;
    let channelPrivKey = keyPair.privateKey;

    let { pubKey, privKey } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
        // cipher: 'aes-256-cbc',
        // passphrase: passphrase
      }
    });

    return { challelPubKey: channelPubKey, channelPrivKey: channelPrivKey, pubKey: pubKey, privKey: privKey };

    //generate channel priv pub and priv pub
  }

  async sign(obj){
    let string = JSON.stringify(Obj);
    let enc = new TextEncoder();
    let encoded = enc(string);
    obj['sig'] = await window.crypto.subtle.sign(
     {
       name: "ECDSA",
       hash: {name: "SHA-512"},
     },
     this.getChannelKeyChain(obj['channel'])['channelPrivKey'],
     encoded
    );
    return obj;
  }

  async verify(obj){
    let sig = obj['sig'];
    //remove
    delete obj['sig'];
    let enc = new TextEncoder();
    let encoded = enc(JSON.stringify(obj));
    return await window.crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: {name: "SHA-512"},
      },
      obj['channelPubKey'],
      sig,
      encoded
    );
  }


  async verifyCaptchaResponse(action,v2,v3){
    if(isInArray(action, combined)){
        //verify v2
        try{
          let token = v2;
          // console.log(token);
          let reCaptchaRes = await axios.post('https://www.google.com/recaptcha/api/siteverify?secret='+secretKeyV2+'&response='+token, {},
          { headers: {  "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" } } );
          // console.log(reCaptchaRes);
          reCaptchaRes = reCaptchaRes['data'];
          // console.log(reCaptchaRes);
          if(typeof(reCaptchaRes) == 'undefined' || reCaptchaRes == 'undefined' || typeof(reCaptchaRes['success']) == 'undefined' || !reCaptchaRes['success']){
            return true;
          }
        }
        catch(error){
          console.log(error);
          throw('reCaptcha');
        }

        //verify v3
        try{
          let token = v3;
          // console.log(token);
          let reCaptchaRes = await axios.post('https://www.google.com/recaptcha/api/siteverify?secret='+secretKeyV3+'&response='+token, {},
          { headers: {  "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" } } );
          // console.log(reCaptchaRes);
          reCaptchaRes = reCaptchaRes['data'];
          // console.log(reCaptchaRes);
          if(typeof(reCaptchaRes) != 'undefined' && reCaptchaRes != 'undefined' && typeof(reCaptchaRes['success']) != 'undefined' && reCaptchaRes['success'] && reCaptchaRes['action'] == action && reCaptchaRes['score'] >= 0.9){
            return  true;
          }
        }
        catch(error){
          console.log(error);
          throw('reCaptcha');
        }
    }
    else if(isInArray(action, v3only)){
      //verify v3
        try{
          let token = req.body.reCaptchaV3;
          // console.log(token);
          let reCaptchaRes = await axios.post('https://www.google.com/recaptcha/api/siteverify?secret='+secretKeyV3+'&response='+token, {},
          { headers: {  "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" } } );
          console.log(reCaptchaRes);
          reCaptchaRes = reCaptchaRes['data'];
          // console.log(reCaptchaRes);
          // DEVMODE && console.log(reCaptchaRes);
          // DEVMODE && console.log(component);

          if(typeof(reCaptchaRes) != 'undefined' && reCaptchaRes != 'undefined' && typeof(reCaptchaRes['success']) != 'undefined' && reCaptchaRes['success'] && reCaptchaRes['action'] == action && reCaptchaRes['score'] >= 0.9){
            return  true;
          }
        }
        catch(error){
          DEVMODE && console.log(error);
          throw('reCaptcha');
        }
    }

    throw('reCaptcha');

  }

  async importKey(pemBinary){
      let importedKey = await window.crypto.subtle.importKey(
            "pkcs8", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
            pemBinary,
            {   //these are the algorithm options
                name: "RSA-OAEP",
                hash: {name: "SHA-512"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
            },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["decrypt"] //"encrypt" or "wrapKey" for public key import or
                        //"decrypt" or "unwrapKey" for private key imports
      );
      return importedKey;
  }

  async rsaFullEncrypt(plain,pubKey){
       let rsaEncrypted;
      try{
        rsaEncrypted = await window.crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        pubKey,
        Buffer.from(plain, 'utf-8')
        );
        // this.DEVMODE && console.log(rsaEncrypted);
        return rsaEncrypted;
      }
      catch(error){
        throw(error);
      }
  }

  async rsaFullDecrypt(enc,pk){
    let ik = await this.importKey(pk);
    return await this.rsaDecrypt(ik,enc);
  }

  async rsaDecrypt(importedKey,encryptedSecretArrayBuffer ){
    let decryptedMessage;
   // try{
     decryptedMessage = await window.crypto.subtle.decrypt(
     {
       name: "RSA-OAEP"
     },
     importedKey,
     encryptedSecretArrayBuffer
     );
     DEVMODE && console.log(decryptedMessage);

      var bufView = new Uint8Array(decryptedMessage);
      var length = bufView.length;
      var rsaDecrypted = '';
      var addition = Math.pow(2,16)-1;

    for(var i = 0;i<length;i+=addition){
        if(i + addition > length){
            addition = length - i;
        }
        rsaDecrypted += String.fromCharCode.apply(null, bufView.subarray(i,i+addition));
    }
    DEVMODE &&  console.log('decryptedMessage:'+rsaDecrypted);
    return rsaDecrypted;

  }

  async verifyEncryptedChallengeResponse(channel, encryptedWhistle,encryptedResponse){
        //decrypt it with my private key
        let whistle = await this.rsaFullDecrypt(encryptedWhistle,this.getChannelKeyChain[channel]['channelPrivKey']);
        let response = await this.aesDecryptB64(encryptedResponse,whistle);
        response = JSON.parse(response);
        //then test the captchas, this will throw if something isn't right
        return await verifyCaptchaResponse("CHALLENGE_RESPONSE",response['v2'],response['v3']);
        //add the guy to the list
  }

  joinChannel(transport,channel,ipfsCID){
    return new Promise( async (resolve) => {
      this.ipfsCID = ipfsCID;
      // TODO: if channel doesn't exist create it first and become owner?


      //Retrieve keys
      let channelKeyChain;
      if(typeof(this.channelKeyChain[channel]) == 'undefined'){
          //generate keys for this channel
          channelKeyChain = this.generateChannelKeyChain();
          this.setChannelKeyChain(channel, channelKeyChain);
      }
      else{
        //get keys from keychain object
        channelKeyChain =  this.getChannelKeyChain(channel);
      }

      //check if we have this channel in our keychain already
      let amiowner = false;
      if(typeof(this.keyChain[channel]['channelPubKey']) != 'undefined'){
        amiowner = this.ownerCheck(channel,channelKeyChain['channelPubKey'])
        if(amiowner){

          //this.publish({ channel: channel, type: "opaqueSayHi", whistleID: this.whistle.getWhistleID(), timestamp });
        }
      }

      if(!amiowner){
        //we are going to announce our join, share our pubkey-chain and request the current participant list
        let pubObj = { fromCID: this.ipfsCID, channel: channel, type: "sayHi", channelPubKey: channelKeyChain['channelPubKey'] };
        transport.publish(pubObj);
      }
      else{
        //  TODOO  this.publish({ type: "opaqueSayHi", to: message.from, QuestPubSub.ownerSayHi({ toCID: message.from, toWhistleID: data['whistleID'], toTime: timestamp, channelParticipantList: this.channelParticipantList[channel], this.channelKeyChain[channel]['pubKey'] ) });
      }

      this.subs[channel] = new Subject();
      transport.subscribe(channel, async(message) => {
          let msgData = JSON.parse(message.data.toString());
          let signatureVerified = await this.verify(msgData);
          if(iamowner && msgData['type'] == "sayHi" && signatureVerified){
            //put together a message with all users whistleid timestamp, hash and sign message with pubkey
            let channelParticipantList = await this.getChannelParticipantList(channel);
            if(this.isParticipant(cList, msgData['channelPubKey'])){
              let {secret, encryptedChannelParticipantList } = this.aesEncryptB64(Buffer.from(JSON.stringify({channelParticipantList: channelParticipantList }), 'utf8').toString('base64'));
              let whistle = this.rsaFullEncrypt(secret, msgData['channelPubKey']);
              this.publish({ type: "ownerSayHi", toChannelPubKey: msgData['channelPubKey'], message: encryptedChannelParticipantList, whistle: whistle });
            }
            else{
              //this is a new guy, maybe we should add them to the list? let's challenge them! you should customize this function!!!
              this.publish({ type: "CHALLENGE", toChannelPubKey: msgData['channelPubKey'] });
            }

          }
          if(iamowner && msgData['type'] == 'CHALLENGE_RESPONSE'  && signatureVerified){
            //we received a challenge response as owner of this channel
            let challengeMastered = await this.verifyEncryptedChallengeResponse(channel,msgData['whistle'], msgData['response'], msgData['channelPubKey']);
            if(challengeMastered){
              let channelParticipantList = await this.getChannelParticipantList(channel);
              let {secret, encryptedChannelParticipantList } = this.aesEncryptB64(Buffer.from(JSON.stringify({ channelParticipantList: channelParticipantList }), 'utf8').toString('base64'));
              let whistle = this.rsaFullEncrypt(secret, msgData['channelPubKey']);
              this.publish({ type: "ownerSayHi", toChannelPubKey: msgData['channelPubKey'], message: encryptedChannelParticipantList, whistle: whistle});
            }
          }
          else if(msgData['type'] == 'CHALLENGE' && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified){
            //owner is challenging us to join, we will complete the challenge and encrypt our public key for the owner with their publickey
            //show captcha screen for user
            this.subs[channel].next({ type: 'CHALLENGE' })
          }
          else if(msgData['type'] == 'ownerSayHi' && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified){
          //WE RECEIVED A USER LIST
          try{
            // decrypt the whistle with our pubKey
            let whistle = this.rsaFullDecrypt(msgData['whistle'], this.getChannelKeyChain(channel)['channelPrivKey']);
            let channelInfo = this.aesDecryptB64(msgData['message'],whistle);
            //decrypt the userlist
              this.setChannelParticipantList(channel,  this.parseParticipantList(channel, channelInfo['channelParticipantList']));;
              this.subs[channel].next({ type: 'ownerSayHi' });
            }
            catch(error){
              //fail silently
              console.log(error);
            }
          }
          else if(msgData['type'] == 'channelMessage' && this.isParticipant(this.channelParticipants[channel]['cList'], msgData['channelPubKey']) && signatureVerified){
            console.log('got message from ' + message.from)
            //decrypt this message with the users public key
            let msg = {};
            msg['message'] = this.aesDecryptB64(msgData['message'].toString('base64'),this.channelParticipantList['pList'].split(',')[this.channelParticipantList['cList'].split(',').indexOf(pubObj['channelPubKey'])]);
            msg['type'] = "channelMessage";
            msg['from'] = message.from;
            this.subs[channel].next(msg);
          }
      });


    });
  }

  async publish(transport, pubObj){
    return new Promise( (resolve) => {
    try {
      if(pubObj['type'] == 'channelMessage'){

        //encrypt message
        let {secret, encryptedB64 } = this.aesEncryptUtf8(pubObj['message'],this.getChannelKeyChain(pubObj['channel'])['pubKey']);
        // pubObj['whistle'] = this.rsaFullEncrypt(secret,this.getChannelKeyChain();
        pubObj['message'] = Buffer.from(encryptedB64,'base64');

      }
      let date = new Date();
      pubObj['timestamp'] =    date.time();
      pubObj['channelPubKey'] = this.getChannelKeyChain(pubObj['channel'])['channelPubKey'];
      pubObj = this.sign(pubObj);
      let dataString = JSON.stringify(pubObj);
      let data = Buffer.from(dataString,'utf8');
      transport.publish(pubObj['channel'], data, (err) => {
        if (err) {
          console.error('error publishing: ', err)
          throw(err);
        } else {
          console.log('successfully published message')
          resolve(true);
        }
      });

    } catch(err) {
      console.log('Failed to publish message', err)
      throw(err);
    }
              // Empty message in view model
    });
  }




}
