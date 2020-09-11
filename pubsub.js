const qCaptcha = require('@questnetwork/quest-image-captcha-js');

const axios = require('axios');
const CryptoJS = require('crypto-js')
const { v4: uuidv4 } = require('uuid');
import { Subject } from "rxjs";

//provisional: https://github.com/PeculiarVentures/webcrypto/issues/19
let WebCrypto;
if(typeof(window.crypto) != 'undefined'){
  WebCrypto = window.crypto;
}
else{
  let { Crypto } = require("@peculiar/webcrypto");
  WebCrypto = new Crypto();
}

function isInArray(value, array) {
  return array.indexOf(value) > -1;
}

// import { GlobalQCaptcha as qCaptcha }  from '@questnetwork/quest-captcha-js';


export class PubSub {
    constructor() {
      //in the future only handle one channel per instanciated class
      this.ipfsCID = "";
      this.subs = {};
      this.channelParticipantList = {};
      this.channelKeyChain = {};
      this.channelNameList = [];
      this.splitter = "-----";
      this.channelHistory = {};
      let uVar;
      this.ipfsId = uVar;
      this.pubSubPeersSub = new Subject();
      this.DEVMODE = false;
      this.captchaCode = {};
      this.captchaRetries = {};
      this.commitNowSub = new Subject();
      this.commitSub = new Subject();
      this.inviteCodes = {};
      this.channelConfig = {};

    }

    isInArray(value, array) {
     return array.indexOf(value) > -1;
   }

   isSubscribed(channel){
     if(typeof(this.subs[channel]) != 'undefined'){
       return true;
     }
     else{
       return false;
     }
   }
   commit(){
     this.commitSub.next(true);
   }

    async createChannel(channelInput, folders = {}){
      //generate keypair
      let channelKeyChain = await this.generateChannelKeyChain({owner:true});
      let democracy = "rep";
      let channelName = channelInput+this.splitter+channelKeyChain['channelPubKey']+this.splitter+channelKeyChain['ownerPubKey']+this.splitter+democracy;
      this.setChannelKeyChain(channelKeyChain,channelName);
      this.setChannelParticipantList({cList: channelKeyChain['channelPubKey'], pList: channelKeyChain['pubKey']},channelName);
      this.addChannelName(channelName);
      return channelName;
    }


    async addChannel(channelNameClean, folders = {}){
      //generate keypair
      this.addChannelName(channelNameClean);
      return channelNameClean;
    }



    ownerCheck(channel, pubKey){
      return ((channel.indexOf(pubKey) > -1) ? true : false);
    }
    isOwner(channel,pubkey = "none"){
      if(pubkey == "none"){
        pubkey = this.getChannelKeyChain(channel)['channelPubKey'];
      }
      return this.ownerCheck(channel,pubkey);
    }
    getOwnerChannelPubKey(channel){
      return channel.split(this.splitter)[1];
    }

    getOwnerPubKey(channel){
      return channel.split(this.splitter)[2];
    }

    parseParticipantList(plist){
      return plist.split(',');
    }
    isParticipant(channel, channelPublicKey){
      let list = this.getChannelParticipantList(channel)['cList'];
      return ((list.indexOf(channelPublicKey) > -1) ? true : false);
    }
    generateChannelParticipantListFromChannelName(channelName){
      let c = channelName.split(this.splitter)[1];
      let p = channelName.split(this.splitter)[2];
      let plist = {};
      plist['cList'] = c;
      plist['pList'] = p;
      return plist;
    }
    getChannelParticipantList(channel = 'all'){
      if(typeof(this.channelParticipantList) == 'undefined'){
        throw('participant list not set');
      }
      if(channel == 'all'){
        return this.channelParticipantList;
      }
      if(typeof(this.channelParticipantList[channel]['cList']) != 'undefined' && typeof(this.channelParticipantList[channel]['pList']) != 'undefined'){
        return this.channelParticipantList[channel];
      }
      else{
        //we don't have a list we must be new here, but we should have keys for this channel in the
        return {};
      }
    }
    getChannelParticipantCListArray(channel){
      return this.getChannelParticipantList(channel)['cList'].split(',');
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
      this.channelParticipantList[channel]['cList'] += ","+channelPubKey;
      this.channelParticipantList[channel]['pList'] += ","+pubKey;
    }

    getChannelNameList(){
      return this.channelNameList;
    }
    setChannelNameList(list){
       this.channelNameList = list;
    }
    addChannelName(channelName){
      this.channelNameList.push(channelName);
    }

    setChannelKeyChain(keychain, channel = "all"){
      if(channel == "all"){
        this.DEVMODE && console.log('Replacing Global Keychain For All Channels...',keychain);
          this.channelKeyChain = keychain;
      }
      else{
        console.log('Adding Channel Keychain...');
        // console.loging('setting...',keychain);
        this.channelKeyChain[channel] = keychain;
      }
    }
    getChannelKeyChain(channel = 'all'){
      console.log('Testing type of channelKeyChain...');
      if(this.DEVMODE && channel == 'all'){
        console.log(JSON.stringify(this.channelKeyChain));
      }
      else if(this.DEVMODE && channel != 'all'){
        console.log(JSON.stringify(this.channelKeyChain[channel]));
      }

      if(typeof(this.channelKeyChain) == 'undefined'){
        throw('undefined')
      }

      else if((channel != 'all' && JSON.stringify(this.channelKeyChain) == '{}') || (channel != 'all' &&  JSON.stringify(this.channelKeyChain) != '{}' && typeof(this.channelKeyChain[channel]) == 'undefined')){
        throw('keychain for this channel not set we need to generate it!');
      }
      else if(JSON.stringify(this.channelKeyChain) == '{}'){
        return {};
      }


      if(channel == 'all'){
        this.DEVMODE && console.log('Retrieving all channelKeyChains...');
        return this.channelKeyChain;
      }

      console.log('Retrieving channelKeyChain [0x200:'+channel+']...');
      return this.channelKeyChain[channel];
    }

    stringToArrayBuffer(string,format){
      if(typeof(format) == 'undefined'){
        format='utf8';
      }
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
      console.log('about to create word array');
      let wordArray = CryptoJS.lib.WordArray.create(this.stringToArrayBuffer(b64,'base64'));
      return this.aesEncryptWordArray(wordArray,whistle);
    }
    aesEncryptUtf8(utf8, whistle = undefined){
      //string to array buffer
      let wordArray = CryptoJS.lib.WordArray.create(this.stringToArrayBuffer(utf8,'utf8'));
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
      // console.log('encryption start...');

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
      // console.log(aesEncryptedB64);
      // console.log('encryption complete!');
      return { secret, aesEncryptedB64 }
    }
    aesDecryptHex(enc,secret, format = 'utf8'){
      let msgB64 = Buffer.from(enc,'hex').toString('base64');
      return this.aesDecryptB64(msgB64, secret, format);
    }
    aesDecryptB64(encryptedQuestFileB64, secret, format = 'utf8'){
      let decryptedQuestFileWordArray;
      try{
        //aes decrypt this file
        let key = CryptoJS.enc.Utf8.parse(secret.slice(0,64));         // Key: Use a WordArray-object instead of a UTF8-string / NodeJS-buffer
        let iv = CryptoJS.enc.Utf8.parse(secret.substr(secret.length-16));
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
        let toHex = decryptedQuestFileWordArray.toString(CryptoJS.enc.Hex);
        return Buffer.from(toHex,'hex').toString('utf8');
      }
      // return "123";
    }

    async generateChannelKeyChain(config = {owner:false}){
      let keyPair =  await WebCrypto.subtle.generateKey({
        name: 'ECDSA',
        namedCurve: 'P-521'
      },
      true,
      ["sign","verify"]);


      let channelPubKeyJWK =  await WebCrypto.subtle.exportKey('jwk',keyPair.publicKey);
      let channelPrivKeyJWK = await WebCrypto.subtle.exportKey('jwk',keyPair.privateKey);

      let channelPubKeyStringify =  JSON.stringify(channelPubKeyJWK);
      let channelPrivKeyStringify = JSON.stringify(channelPrivKeyJWK);
      let channelPubKey = Buffer.from(channelPubKeyStringify,'utf8').toString('hex');
      let channelPrivKey =  Buffer.from(channelPrivKeyStringify,'utf8').toString('hex');

      let oaepKeyPair = await WebCrypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-512"
        },
        true,
        ["encrypt", "decrypt"]
      );

      let pubKeyArrayBuffer =  await WebCrypto.subtle.exportKey('spki',oaepKeyPair.publicKey);
      let pubKey = Buffer.from(pubKeyArrayBuffer).toString('hex');
      let privKeyArrayBuffer = await WebCrypto.subtle.exportKey('pkcs8',oaepKeyPair.privateKey);
      let privKey = Buffer.from(privKeyArrayBuffer).toString('hex');
      let channelKeyChain = { channelPubKey: channelPubKey, channelPrivKey: channelPrivKey, pubKey: pubKey, privKey: privKey };


      if(!config.owner){
        return channelKeyChain;
      }

      let oaepOwnerKeyPair = await WebCrypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-512"
        },
        true,
        ["encrypt", "decrypt"]
      );

      if(config['owner']){
        let ownerPubKeyArrayBuffer =  await WebCrypto.subtle.exportKey('spki',oaepOwnerKeyPair.publicKey);
        channelKeyChain['ownerPubKey'] = Buffer.from(pubKeyArrayBuffer).toString('hex');
        let ownerPrivKeyArrayBuffer = await WebCrypto.subtle.exportKey('pkcs8',oaepOwnerKeyPair.privateKey);
        channelKeyChain['ownerPrivKey'] = Buffer.from(privKeyArrayBuffer).toString('hex');
      }


      // console.log(channelKeyChain);
      return channelKeyChain;

      //generate channel priv pub and priv pub
    }


    async importKey(alg,format,keyenc,key){
      if(format == 'jwk'){
        key = JSON.parse(Buffer.from(key,keyenc).toString('utf8'));
      }
      //else if(format == 'pkcs8'){
      //   key = Buffer.from(key,keyenc).toString('base64');
      // }
      else{
        let keyBuf = Buffer.from(key,keyenc);
        key = this.bufferToArrayBuffer(keyBuf);
      }
        let action;
        if(alg == "RSA-OAEP" && format == 'pkcs8'){
          action = ["decrypt"];
        }
        else if(alg == "RSA-OAEP" && format == 'spki'){
          action = ["encrypt"];
        }
        else if(alg == "ECDSA" && format == 'jwk'){
          action = key['key_ops'];
        }
        let keyConfig = {   //these are the algorithm options
            name: alg,
            hash: {name: "SHA-512"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
        }
        if(alg == "ECDSA"){
          keyConfig['namedCurve'] = "P-521";
        }

        // console.log(key);
        // console.log(key);
        let importedKey = await WebCrypto.subtle.importKey(
              format, //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
              key,
              keyConfig,
              true, //whether the key is extractable (i.e. can be used in exportKey)
              action //"encrypt" or "wrapKey" for public key import or
                          //"decrypt" or "unwrapKey" for private key imports
        );
        return importedKey;
    }

    bufferToArrayBuffer(buf) {
        var ab = new ArrayBuffer(buf.length);
        var view = new Uint8Array(ab);
        for (var i = 0; i < buf.length; ++i) {
            view[i] = buf[i];
        }
        return ab;
    }

    async sign(obj){
      // console.log('signing!');
      // console.log(obj['channel']);
      let keyChain = this.getChannelKeyChain(obj['channel']);
      let keyHex = keyChain['channelPrivKey'];
      let key = await this.importKey('ECDSA','jwk','hex',keyHex);
      let string = JSON.stringify(obj);
      let encoded = new TextEncoder().encode(string);
      let sigArrayBuffer = await WebCrypto.subtle.sign(
       {
         name: "ECDSA",
         namedCurve: "P-521",
         hash: {name: "SHA-512"},
       },
       key,
       encoded
      );
      obj['sig'] = Buffer.from(sigArrayBuffer).toString('hex');
      return obj;
    }

    async verify(obj){
      let keyHex = obj['channelPubKey'];
      let key = await this.importKey('ECDSA','jwk','hex',keyHex);
      let sig = this.bufferToArrayBuffer(Buffer.from(obj['sig'], 'hex'));
      //remove
      delete obj['sig'];
      let encoded = new TextEncoder().encode(JSON.stringify(obj));
      return await WebCrypto.subtle.verify(
        {
          name: "ECDSA",
          hash: {name: "SHA-512"},
        },
        key,
        sig,
        encoded
      );
    }



    async rsaFullEncrypt(plain,pubKey){
      // console.log('encrypting');
      let key = await this.importKey('RSA-OAEP','spki','hex',pubKey);
      // console.log(key);
         let rsaEncrypted;
        try{
          rsaEncrypted = await WebCrypto.subtle.encrypt(
          {
            name: "RSA-OAEP"
          },
          key,
          Buffer.from(plain, 'utf8')
          );
          return Buffer.from(rsaEncrypted).toString('hex');
        }
        catch(error){
          throw(error);
        }
    }

    async rsaFullDecrypt(enc,pk){
      // console.log('dencrypting',enc);
      let key = await this.importKey('RSA-OAEP','pkcs8','hex',pk);
      let messageBuf = Buffer.from(enc,'hex');
      let messageBufArray = this.bufferToArrayBuffer(messageBuf);
      return await this.rsaDecrypt(key,messageBufArray);
    }

    async rsaDecrypt(importedKey,encryptedSecretArrayBuffer ){
      let decryptedMessage;
     // try{
       decryptedMessage = await WebCrypto.subtle.decrypt(
       {
         name: "RSA-OAEP"
       },
       importedKey,
       encryptedSecretArrayBuffer
       );
       // DEVMODE && console.log(decryptedMessage);

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
      // DEVMODE &&  console.log('decryptedMessage:'+rsaDecrypted);
      return rsaDecrypted;

    }

    async verifyChallengeResponse(channel, code,chPubKey){
        //test for invite token
        // console.log("RESPONSE:",code);
        let ivC = this.inviteCodes[channel]['items'].filter(i => i['code'] == code);
        for(let i=0;i<this.inviteCodes[channel]['items'].length;i++){
          if(this.inviteCodes[channel]['items'][i]['code'] == code && this.inviteCodes[channel]['items'][i]['max'] > this.inviteCodes[channel]['items'][i]['used']){
            this.inviteCodes[channel]['items'][i]['used']++;
            this.commitNow();
            return true;
          }
        }

        //test for captcha
        // console.log(code);
        // console.log(this.captchaCode[chPubKey]);
        if(code == this.captchaCode[chPubKey]){
          return true;
        }
        return false;
    }


     getPubKeyFromChannelPubKey(channel,channelPubKey){
      let channelParticipantList = this.getChannelParticipantList(channel);
      let array = channelParticipantList['pList'].split(',');
      let index = channelParticipantList['cList'].split(',').indexOf(channelPubKey);
      return array[index];
    }



     joinChannel(transport,channel){
      return new Promise( async (resolve) => {
        // this.ipfsCID =  this.ipfs.ipfsNode.id();
        // TODO: if channel doesn't exist create it first and become owner?

        console.log('joining channel...');
        //Retrieve keys
        let channelKeyChain = {};
        console.log('Getting channel keychain... [0x0200:'+channel+']')
        try{
          console.log('Calling getChannelKeyChain... [0x0200:'+channel+']');
          channelKeyChain =  this.getChannelKeyChain(channel);
        }catch(e){
          if(e == 'undefined'){
            throw('fatal error - channelkeychain undefined [0x0200:'+channel+']');
          }
          //keychain is not set
          console.log('No key chain found. Generating new keys... [0x0200:'+channel+']');
          channelKeyChain = await this.generateChannelKeyChain();
          this.DEVMODE && console.log(channelKeyChain);
          this.setChannelKeyChain(channelKeyChain,channel);
        }

        console.log('Keychain start complete... [0x0200:'+channel+']');
        let amiowner = false;
        console.log('Testing owner status... [0x0200:'+channel+']');
        if(typeof(channelKeyChain) == 'undefined'){
          console.log('E:KEYCHAIN_CORRUPT');
          return false;
        }
        if(typeof(channelKeyChain['channelPubKey']) != 'undefined'){
           amiowner = this.ownerCheck(channel,channelKeyChain['channelPubKey']);
        }

        if(amiowner){
          console.log('We are the owner! [0x0200:'+channel+']');
          // TO DO this.publish({ channel: [0x0200:'+channel+']'channel, type: "opaqueSayHi", whistleID: this.whistle.getWhistleID(), timestamp });
        }
        else{
          console.log('We are not the owner! SayingHi... [0x0200:'+channel+']');
          //we are going to announce our join, share our pubkey-chain and request the current participant list
          let pubObj = { channel: channel, type: "sayHi", toChannelPubKey: this.getOwnerChannelPubKey(channel), channelPubKey: channelKeyChain['channelPubKey'] };
          this.publish(transport,pubObj);
        }

        console.log('Fetching Subscription... [0x0200:'+channel+']');
        this.subs[channel] = new Subject();
        this.channelHistory[channel] = [];
        console.log('Subscribing... [0x0200:'+channel+']');
        this.channelSubscribe(transport,channel,amiowner);
        console.log('Join Complete [0x0200:'+channel+']');
        resolve(true);
      });
    }

    commitNow(){
      this.commitNowSub.next(true);
    }


    async channelSubscribe(transport,channel,amiowner){
        let peers = await transport.peers(channel);
        console.log('PubSub Peers:',peers);
        transport.subscribe(channel, async(message) => {
          console.log('New message!',message);
            let msgData = JSON.parse(message.data.toString('utf8'));
            this.DEVMODE && console.log(msgData);
            this.DEVMODE && console.log('Verifying signature...');
            let signatureVerified = await this.verify(msgData);
            this.DEVMODE && console.log('Signature:',signatureVerified);
            if(amiowner && msgData['type'] == "sayHi" && signatureVerified){
              //put together a message with all users whistleid timestamp, hash and sign message with pubkey
              if(this.isParticipant(channel, msgData['channelPubKey'])){
                this.publish(transport,{ channel: msgData['channel'], type: "ownerSayHi", toChannelPubKey: msgData['channelPubKey'], message: JSON.stringify({channelParticipantList: this.getChannelParticipantList(channel) })});
              }
              else{
                //this is a new guy, maybe we should add them to the list? let's challenge them! you should customize this function!!!
                //generate the captcha
                console.log('qps:',this.getChallengeFlag(channel));
                //TO DO: CHECK FOR UNUSED INVITE CODES FOR THIS CHANNEL
                console.log('qps:',typeof this.inviteCodes[channel] == 'object' );
                if(this.getChallengeFlag(channel)){
                  console.log('challengeFlag activated');
                  let {captchaCode,captchaImageBuffer} = await qCaptcha.getCaptcha();
                  this.captchaCode[msgData['channelPubKey']] = captchaCode;
                  this.publish(transport,{ channel: msgData['channel'], type: "CHALLENGE", toChannelPubKey: msgData['channelPubKey'], message: captchaImageBuffer });
                }
                else if(typeof this.inviteCodes[channel] != 'undefined' && this.inviteCodes[channel].length > 0){
                  this.publish(transport,{ channel: msgData['channel'], type: "CHALLENGE", toChannelPubKey: msgData['channelPubKey'] });
                }
              }
            }
            // if(amiowner && msgData['type'] == 'CHALLENGE_RESPONSE'  && signatureVerified && (((Object.keys(this.captchaRetries).length === 0 && this.captchaRetries.constructor === Object) || typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined') || this.captchaRetries[msgData['channelPubKey']] < 2)){
            if( msgData['type'] == 'CHALLENGE_RESPONSE'  && signatureVerified && (((Object.keys(this.captchaRetries).length === 0 && this.captchaRetries.constructor === Object) || typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined') || this.captchaRetries[msgData['channelPubKey']] < 2)){
              console.log('received challenge response');
              //we received a challenge response as owner of this channel
              let whistle = await this.rsaFullDecrypt(msgData['whistle'],this.getChannelKeyChain(channel)['ownerPrivKey']);
              let response = await this.aesDecryptHex(msgData['response'],whistle);
              response = JSON.parse(response);
              if(typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined'){
                this.captchaRetries[msgData['channelPubKey']] = 1
              }
              else{
                this.captchaRetries[msgData['channelPubKey']] = 2;
              }

              let challengeMastered = await this.verifyChallengeResponse(msgData['channel'], response['code'], msgData['channelPubKey']);
              if(challengeMastered){
                //add the guy
                console.log(msgData['channelPubKey']);
                let newUserChannelPubKey = msgData['channelPubKey'];
                console.log(response['pubKey']);
                let newUserPubKey = response['pubKey'];
                this.addChannelParticipant(msgData['channel'],newUserChannelPubKey,newUserPubKey);
                let channelParticipantList =  this.getChannelParticipantList(msgData['channel']);
                // this.config.commitNow();rue
                this.commitNow();
                let channelParticipantCList =  this.getChannelParticipantCListArray(msgData['channel']);
                for(let cPK of channelParticipantCList){
                  this.publish(transport,{ channel: msgData['channel'], type: "ownerSayHi", toChannelPubKey: cPK, message: JSON.stringify({ channelParticipantList: channelParticipantList })});
                }

              }
            }
            else if(!amiowner && msgData['type'] == 'CHALLENGE' && msgData['channelPubKey'] == this.getOwnerChannelPubKey(channel) && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified){

              //see if we have an invite token for this
              if(typeof this.inviteCodes[msgData['channel']] != 'undefined' && typeof this.inviteCodes[msgData['channel']]['token'] != 'undefined'){
                //try the token first
                let ownerChannelPubKey = this.getOwnerChannelPubKey(channel);
                let pubObj = {
                  channel: channel,
                  type: 'CHALLENGE_RESPONSE',
                  toChannelPubKey: ownerChannelPubKey,
                  response: { code: this.inviteCodes[msgData['channel']]['token'] }
                }
                // console.log("THIS IS IT OUR INVITE:",this.inviteCodes[msgData['channel']]['token']);
                // console.log(pubObj);
                this.publish(transport,pubObj);
              }

              //show captcha screen foer user
              console.log('pushing challenge to view...');
              //owner is challenging us to join, we will complete the challenge and encrypt our public key for the owner with their publickey
              this.subs[channel].next({ type: 'CHALLENGE', captchaImageBuffer: msgData['message'] })
            }
            else if(!amiowner && msgData['type'] == 'ownerSayHi' && msgData['channelPubKey'] == this.getOwnerChannelPubKey(channel) && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified){
            //WE RECEIVED A USER LIST
              try{
              // decrypt the whistle with our pubKey
              let whistle = await this.rsaFullDecrypt(msgData['whistle'], this.getChannelKeyChain(channel)['privKey']);
              let channelInfo = JSON.parse(this.aesDecryptHex(msgData['message'],whistle));
              //decrypt the userlist
              console.log('Got Channel Info: ',channelInfo);
                this.setChannelParticipantList(channelInfo['channelParticipantList'],channel);
                this.commitNow();
                this.subs[channel].next({ type: 'ownerSayHi' });
              }
              catch(error){
                //fail silently
                console.log(error);
              }
            }
            else if(msgData['type'] == 'CHANNEL_MESSAGE' && this.isParticipant(channel, msgData['channelPubKey']) && signatureVerified){
              this.DEVMODE && console.log('got message from:')
              this.DEVMODE && console.log('ipfsCID:',message.from)
              this.DEVMODE && console.log('channelPubKey:',msgData['channelPubKey']);
              //decrypt this message with the users public key
              let msg = {};
              let pubkey = this.getPubKeyFromChannelPubKey(msgData['channel'],msgData['channelPubKey']);
              this.DEVMODE && console.log('Encrypted Message: ',msgData['message']);
              // console.log('PubKey: ',pubkey);
              msg['message'] = this.aesDecryptHex(msgData['message'],pubkey);
              this.DEVMODE && console.log('Decrypted Message: ',msg['message']);
              msg['type'] = "CHANNEL_MESSAGE";
              msg['from'] = message.from;
              msg['channelPubKey'] = msgData['channelPubKey'];
              if(msg['from'] == this.getIpfsId()['id']){
                msg['self'] = true;
              }else{
                msg['self'] = false;
              }


              // if(typeof(this.channelHistory[channel]) == 'undefined'){
                // this.channelHistory[channel] = [];
              // }
              this.channelHistory[channel].push(msg);
              this.subs[channel].next(msg);
            }
        });
    }

    getIpfsId(){
      return this.ipfsId;
    }
    setIpfsId(id){
      this.ipfsId = id;
    }

    setPubSubPeers(peers){
      this.pubSubPeersSub.next(peers);
    }


     getChannelHistory(channel){
      return this.channelHistory[channel];
    }

    async publish(transport,pubObj){
      return new Promise( async(resolve) => {
       try {
        console.log('Publishing:');
        console.log(pubObj);
        if(pubObj['type'] == 'CHANNEL_MESSAGE'){
          //encrypt message
          this.DEVMODE && console.log('Encrypting CHANNEL_MESSAGE...');
          let {secret, aesEncryptedB64 } = this.aesEncryptUtf8(pubObj['message'],this.getChannelKeyChain(pubObj['channel'])['pubKey']);
          pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        else if(pubObj['type'] == 'CHALLENGE_RESPONSE'){
          //encrypt response
          this.DEVMODE && console.log('Encrypting CHALLENGE_RESPONSE...');
          //add fields to response
          pubObj['response']['pubKey'] = this.getChannelKeyChain(pubObj['channel'])['pubKey'];
          let {secret, aesEncryptedB64 } = this.aesEncryptUtf8(JSON.stringify(pubObj['response']));
          pubObj['whistle'] = await this.rsaFullEncrypt(secret,this.getOwnerPubKey(pubObj['channel']));
          pubObj['response'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        else if(pubObj['type'] == 'PRIVATE_MESSAGE' || pubObj['type'] == 'ownerSayHi'){
          //encrypt response
          this.DEVMODE && console.log('Encrypting PRIVATE_MESSAGE...');
          let {secret, aesEncryptedB64 } = this.aesEncryptUtf8(pubObj['message']);
          pubObj['whistle'] = await this.rsaFullEncrypt(secret,this.getPubKeyFromChannelPubKey(pubObj['channel'],pubObj['toChannelPubKey']));
          pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        else if(pubObj['type'] == "sayHi"){
          // let {secret, aesEncryptedB64 } = this.aesEncryptUtf8(pubObj['message']);
          // pubObj['whistle'] = await this.rsaFullEncrypt(secret,this.getOwnerPubKey(pubObj['channel']));
          // pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        let date = new Date();
        pubObj['timestamp'] = date.getTime();
        pubObj['channelPubKey'] = this.getChannelKeyChain(pubObj['channel'])['channelPubKey'];
        pubObj = await this.sign(pubObj);
        this.DEVMODE && console.log('Signed Message Object:',pubObj);
        let dataString = JSON.stringify(pubObj);
        this.DEVMODE && console.log('Signed Message DataString:',dataString);
        let data = Buffer.from(dataString,'utf8');
        this.DEVMODE && console.log('Publishing message... [0x200]');
        try{
          console.log('PubSub LS:',await transport.ls());
          console.log('PubSub Channel: ',pubObj['channel']);
          let pubSubPeers = await transport.peers(pubObj['channel']);
          this.setPubSubPeers(pubSubPeers.length);
          console.log('PubSub Peers:',pubSubPeers);
          await transport.publish(pubObj['channel'], data);
          console.log('Successfully published message');
          resolve(true);
        }
        catch(e){
          console.error('Failed to publish message', e)
          throw(e);
        }
      } catch(err) {
        console.log('Failed to publish message', err)
        throw(err);
      }
                // Empty message in view model
      });
    }


    getInviteCodes(channel = 'all'){
      if(channel == 'all'){
        return this.inviteCodes;
      }
      else{
        return this.inviteCodes[channel];
      }
    }
    addInviteCode(channel,link,code,newInviteCodeMax){
      if(typeof this.inviteCodes[channel] == 'undefined'){
         this.inviteCodes[channel] = {};
      }
      if(typeof this.inviteCodes[channel]['codes'] == 'undefined'){
         this.inviteCodes[channel]['codes'] = {}
      }
      if(typeof this.inviteCodes[channel]['links'] == 'undefined'){
         this.inviteCodes[channel]['links'] = [];
      }
      if(typeof this.inviteCodes[channel]['items'] == 'undefined'){
         this.inviteCodes[channel]['items'] = [];
      }

      this.inviteCodes[channel]['codes'][link] = code ;
      this.inviteCodes[channel]['links'].push(  link  );
      this.inviteCodes[channel]['items'].push({ max: newInviteCodeMax, used: 0, link: link, code:  code});
      this.commitNow();
      return link;
    }
    addInviteToken(channel,token){
      if(typeof this.inviteCodes[channel] == 'undefined'){
         this.inviteCodes[channel] = {};
      }
      this.inviteCodes[channel]['token'] = token;
      this.commitNow();
      return true;
    }
    removeInviteCode(channel, link){
      delete this.inviteCodes[channel]['codes'][link];
      this.inviteCodes[channel]['links'] = this.inviteCodes[channel]['links'].filter(i => i !== link);
      this.inviteCodes[channel]['items'] = this.inviteCodes[channel]['items'].filter(i => i['link'] !== link);
      this.commitNow();
      return true;
    }
    setInviteCodes(inviteObject, channel = 'all'){
      if(channel == 'all'){
        this.inviteCodes = inviteObject;
      }
      else{
          this.inviteCodes[channel] = inviteObject;
      }
      this.commitNow();
      return true;
    }




    getChallengeFlag(ch){
      if(typeof this.channelConfig[ch] != 'undefined' && typeof this.channelConfig[ch]['challengeFlag'] != 'undefined'){
        return this.channelConfig[ch]['challengeFlag']
      }
      else{
        return 0;
      }
    }
    setChallengeFlag(ch, value){
      if(typeof this.channelConfig[ch] == 'undefined'){
        this.channelConfig[ch] = {};
      }
      this.channelConfig[ch]['challengeFlag'] = value;
      this.commit();
    }
    getChannelConfig(ch = 'all'){
      if(ch == 'all'){
         return this.channelConfig;
      }
      else{
        if(typeof this.channelConfig[ch] != 'undefined'){
         return this.channelConfig[ch];
        }
        else{
         return {};
        }
      }
    }
    setChannelConfig(config, ch = 'all'){
      if(ch == 'all'){
         this.channelConfig = config;
      }
      else{
         this.channelConfig[ch] = config;
      }
      this.commit();
    }
  }
