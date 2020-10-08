const qCaptcha = require('@questnetwork/quest-image-captcha-js');

const CryptoJS = require('crypto-js')
const { v4: uuidv4 } = require('uuid');
import { Subject } from "rxjs";


import { NativeCrypto } from "@questnetwork/quest-crypto-js";
import { UtilitiesInstance } from "@questnetwork/quest-utilities-js";


export class PubSub {
    constructor() {
      this.utilities = new UtilitiesInstance();
      this.crypto = new NativeCrypto();


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
      this.incomingFavoriteRequestList = [];

      this.heartbeatInterval = {};
      this.myLastHeartbeat = 0;
      this.alive = [];
      this.aliveHistory = [];

      this.socialProfiles = {};
      this.socialSharedWith = [];
      this.socialLinks = {};

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

    async createChannel(channelInput){
      //generate keypair
      let channelKeyChain = await this.generateChannelKeyChain({owner:true});
      let democracy = "rep";
      let channelName = channelInput+this.splitter+channelKeyChain['channelPubKey']+this.splitter+channelKeyChain['ownerPubKey']+this.splitter+democracy;
      this.setChannelKeyChain(channelKeyChain,channelName);
      this.setChannelParticipantList({cList: channelKeyChain['channelPubKey'], pList: channelKeyChain['pubKey']},channelName);
      this.addChannelName(channelName);
      return channelName;
    }


    async addChannel(channelNameClean){
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
    getIncomingFavoriteRequests(){
      return this.incomingFavoriteRequestList;
    }
    setIncomingFavoriteRequests(list){
       this.incomingFavoriteRequestList = list;
    }
    removeIncomingFavoriteRequest(pubKey){
       this.incomingFavoriteRequestList = this.incomingFavoriteRequestList.filter(e => e['pubKey'] != pubKey);
    }
    addChannelName(channelName){
      this.channelNameList.push(channelName);
    }

    setChannelKeyChain(keychain, channel = "all"){
      console.log('PubSub setChannelKeyChain: ',channel);
      console.log('PubSub setChannelKeyChain: ',keychain);

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
        console.log(this.channelKeyChain);
      }
      else if(this.DEVMODE && channel != 'all'){
        console.log(this.channelKeyChain[channel]);
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



    async generateChannelKeyChain(config = {owner:false}){
      let keyPair = await this.crypto.ec.generateKeyPair();
      let oaepKeyPair = await this.crypto.rsa.generateKeyPair();

      let channelPubKey = keyPair['pubKey'];
      let channelPrivKey =  keyPair['privKey'];
      let pubKey = oaepKeyPair['pubKey'];
      let privKey = oaepKeyPair['privKey'];
      let channelKeyChain = { channelPubKey: channelPubKey, channelPrivKey: channelPrivKey, pubKey: pubKey, privKey: privKey };


      if(!config.owner){
        return channelKeyChain;
      }

      let oaepOwnerKeyPair = await this.crypto.rsa.generateKeyPair();

      if(config['owner']){
        channelKeyChain['ownerPubKey'] = oaepOwnerKeyPair['pubKey'];
        channelKeyChain['ownerPrivKey'] = oaepOwnerKeyPair['privKey']
      }

      return channelKeyChain;
    }

    async sign(obj){
      let keyChain = this.getChannelKeyChain(obj['channel']);
      let keyHex = keyChain['channelPrivKey'];
      console.log("Crypto: Signing...")
      return await this.crypto.ec.sign(obj, keyChain['channelPrivKey']);
    }

    async verify(obj){
      let keyHex = obj['channelPubKey'];
      return await this.crypto.ec.verify(obj, keyHex);
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

    isAlive(channelPubKey){
      let channels = Object.keys(this.alive);
      // console.log(channels);
      for(let channel of channels){
        if( this.utilities.inArray(this.alive[channel],channelPubKey) ){
          return true;
        }

      }

      channels = Object.keys(this.aliveHistory);
      // console.log(channels);
      for(let channel of channels){
        if( this.utilities.inArray(this.aliveHistory[channel].flat(),channelPubKey) ){
          return true
        }
      }

      return false;
    }
    async sendHeartbeat(transport,channel){
      try{
        console.log('sending heartbeat in: ',channel);
        if(typeof this.aliveHistory[channel] == 'undefined'){
          this.aliveHistory[channel] = [];
        }

        if(typeof this.aliveHistory[channel][1] != 'undefined'){
          this.aliveHistory[channel][2] = this.aliveHistory[channel][1];
        }
        if(typeof this.aliveHistory[channel][0] != 'undefined'){
          this.aliveHistory[channel][1] = this.aliveHistory[channel][0];
        }

        this.aliveHistory[channel][0] = JSON.parse(JSON.stringify(this.alive[channel]));

        this.alive[channel] = [];

        console.log('quest-pubsub-js: Checking to send Heartbeat');

        // if(this.myLastHeartbeat < new Date().getTime()-60*2){
        //send heartbeat
        this.publish(transport,{ channel: channel, type: "HEARTBEAT", message: JSON.stringify({}) });
        this.myLastHeartbeat =  new Date().getTime();
      // }
      }catch(e){}
      await this.utilities.delay(1000*60);
      this.sendHeartbeat(transport,channel);
    }

    async channelSubscribe(transport,channel,amiowner){
        let peers = await transport.peers(channel);
        console.log('PubSub Peers:',peers);
        this.alive[channel] = [];
        setTimeout( () => {
          this.sendHeartbeat(transport,channel);
        },5000);

        transport.subscribe(channel, async(message) => {


          console.log('New message!',message);
            let msgData = JSON.parse(message.data.toString('utf8'));
            if(typeof msgData == 'string'){
              msgData = JSON.parse(msgData);
            }
             console.log(msgData);
             // console.log('Verifying signature...');

             let msgHash = "";
             if(msgData['channelPubKey'] != 'undefined' && msgData['sig'] != 'undefined'){
               msgHash = msgData['channelPubKey']+'-----'+msgData['sig'];
             }

            let signatureVerified = await this.verify(msgData);

            // console.log('Signature:',signatureVerified);
            if(amiowner && msgData['type'] == "sayHi" && signatureVerified){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);
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
                else if(typeof this.inviteCodes[channel] != 'undefined' ){
                  this.publish(transport,{ channel: msgData['channel'], type: "CHALLENGE", toChannelPubKey: msgData['channelPubKey'] });
                }
              }
            }
            // if(amiowner && msgData['type'] == 'CHALLENGE_RESPONSE'  && signatureVerified && (((Object.keys(this.captchaRetries).length === 0 && this.captchaRetries.constructor === Object) || typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined') || this.captchaRetries[msgData['channelPubKey']] < 2)){
            else if(amiowner && msgData['type'] == 'CHALLENGE_RESPONSE'  && signatureVerified && (((Object.keys(this.captchaRetries).length === 0 && this.captchaRetries.constructor === Object) || typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined') || this.captchaRetries[msgData['channelPubKey']] < 2)){
              console.log('PubSub: Received challenge response!');
              //we received a challenge response as owner of this channel
              let whistle = await this.crypto.rsa.fullDecrypt(msgData['whistle'],this.getChannelKeyChain(channel)['ownerPrivKey']);
              let response = await this.crypto.aes.decryptHex(msgData['response'],whistle);

              console.log(response);
              if(typeof response == 'string'){
                response = JSON.parse(response);
              }
              console.log(response);

              if(typeof(this.captchaRetries[msgData['channelPubKey']]) == 'undefined'){
                this.captchaRetries[msgData['channelPubKey']] = 1
              }
              else{
                this.captchaRetries[msgData['channelPubKey']] = 2;
              }

              console.log('Verifying challenge response:'+response['code']);
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
              this.subs[channel].next({ msgHash: msgHash, type: 'CHALLENGE', captchaImageBuffer: msgData['message'] })
            }
            else if(!amiowner && msgData['type'] == 'ownerSayHi' && msgData['channelPubKey'] == this.getOwnerChannelPubKey(channel) && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified){
            //WE RECEIVED A USER LIST
              this.alive[msgData['channel']].push(msgData['channelPubKey']);

              try{
              // decrypt the whistle with our pubKey
              let whistle = await this.crypto.rsa.fullDecrypt(msgData['whistle'], this.getChannelKeyChain(channel)['privKey']);
              let channelInfo = this.crypto.aes.decryptHex(msgData['message'],whistle);
              //decrypt the userlist
              console.log('Got Channel Info: ',channelInfo);
                this.setChannelParticipantList(channelInfo['channelParticipantList'],channel);
                this.commitNow();
                this.subs[channel].next({ msgHash: msgHash, type: 'ownerSayHi' });
              }
              catch(error){
                //fail silently
                console.log(error);
              }
            }
            else if( msgData['type'] == 'HEARTBEAT' && this.isParticipant(channel, msgData['channelPubKey']) && signatureVerified){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);
            }
            else if(msgData['type'] == 'CHANNEL_MESSAGE' && this.isParticipant(channel, msgData['channelPubKey']) && signatureVerified){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);

              this.DEVMODE && console.log('got message from:')
              this.DEVMODE && console.log('ipfsCID:',message.from)
              this.DEVMODE && console.log('channelPubKey:',msgData['channelPubKey']);
              //decrypt this message with the users public key
              let msg = {};
              let pubkey = this.getPubKeyFromChannelPubKey(msgData['channel'],msgData['channelPubKey']);
              this.DEVMODE && console.log('Encrypted Message: ',msgData['message']);
              // console.log('PubKey: ',pubkey);
              msg['id'] = uuidv4();
              msg['message'] = this.crypto.aes.decryptHex(msgData['message'],pubkey);
              this.DEVMODE && console.log('Decrypted Message: ',msg['message']);
              msg['type'] = "CHANNEL_MESSAGE";
              msg['from'] = message.from;
              msg['channelPubKey'] = msgData['channelPubKey'];
              msg['channel'] = channel;
              if(msg['from'] == this.getIpfsId()['id']){
                msg['self'] = true;
              }else{
                msg['self'] = false;
              }

              if(typeof msgHash.length > 0){
                msg['masgHash'] = msgHash;
              }

              this.channelHistory[channel].push(msg);
              this.subs[channel].next(msg);
            }
            else if(msgData['type'] == 'SHARE_PUBLIC_SOCIAL' && this.isParticipant(channel, msgData['channelPubKey']) && signatureVerified){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);

              console.log(msgData);
              let pubkey = this.getPubKeyFromChannelPubKey(msgData['channel'],msgData['channelPubKey']);
              let signedSocialObj = this.crypto.aes.decryptHex(msgData['message'],pubkey);
              console.log(signedSocialObj);
              let isVerified = await this.crypto.ec.verify(signedSocialObj,signedSocialObj['key']['pubKey']);
              if(isVerified){
                console.log("PubSub: Received Social Profile ...",signedSocialObj)
                this.socialProfiles[signedSocialObj['key']['pubKey']] = signedSocialObj;
                if(typeof this.socialLinks[msgData['channelPubKey']] == 'undefined'){
                  this.socialLinks[msgData['channelPubKey']] = []
                }
                this.socialLinks[msgData['channelPubKey']].push(signedSocialObj['key']['pubKey']);
                this.commitNow();
                let pubObj = { channel: channel, toChannelPubKey: msgData['channelPubKey'], type: "RECEIVED_SOCIAL", message: signedSocialObj['key']['pubKey'] };
                this.publish(transport, pubObj);
              }

            }
            else if( (msgData['type'] == "REQUEST_FAVORITE" || msgData['type'] == 'SHARE_PRIVATE_SOCIAL') && this.isParticipant(channel, msgData['channelPubKey']) && msgData['toChannelPubKey'] == this.getChannelKeyChain(channel)['channelPubKey'] && signatureVerified ){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);

              console.log('PubSub: Received Private Social or request favorite!');


              try{
                let whistle = await this.crypto.rsa.fullDecrypt(msgData['whistle'], this.getChannelKeyChain(channel)['privKey']);
                let decryptedMessageObj = this.crypto.aes.decryptHex(msgData['message'],whistle);

                      if(msgData['type'] == 'SHARE_PRIVATE_SOCIAL'){
                        console.log('PubSub: Received Private Social');
                          let isVerified = await this.crypto.ec.verify(decryptedMessageObj,decryptedMessageObj['key']['pubKey']);
                          if(isVerified){
                            this.socialProfiles[decryptedMessageObj['key']['pubKey']] = decryptedMessageObj;
                            if(typeof this.socialLinks[msgData['channelPubKey']] == 'undefined'){
                              this.socialLinks[msgData['channelPubKey']] = []
                            }
                            this.socialLinks[msgData['channelPubKey']].push(decryptedMessageObj['key']['pubKey']);
                            this.commit();

                            let pubObj = { channel: channel, toChannelPubKey: msgData['channelPubKey'], type: "RECEIVED_SOCIAL", message: decryptedMessageObj['key']['pubKey'] };
                            this.publish(transport, pubObj);
                          }
                      }
                      else if(msgData['type'] == "REQUEST_FAVORITE"){
                        console.log('PubSub: Received Favorite Request');
                        //add request to incoming request list and show in channel list
                        if(!this.isInFavoriteRequestList(decryptedMessageObj['pubKey'])){
                          this.incomingFavoriteRequestList.push(decryptedMessageObj);
                        }else{
                          for(let i=0;i<this.incomingFavoriteRequestList.length;i++){
                            if(this.incomingFavoriteRequestList[i]['pubKey'] == decryptedMessageObj['pubKey']){
                              this.incomingFavoriteRequestList[i]['invite'] = decryptedMessageObj['invite']
                            }
                          }
                        }
                      }


              }
              catch(error){
                //fail silently
                console.log(error);
              }

            }
            else if(msgData['type'] == 'RECEIVED_SOCIAL' && this.isParticipant(channel, msgData['channelPubKey']) && signatureVerified){
              this.alive[msgData['channel']].push(msgData['channelPubKey']);

              //WE RECEIVED A READ RECEIPT
                try{
                // decrypt the whistle with our pubKey
                  let whistle = await this.crypto.rsa.fullDecrypt(msgData['whistle'], this.getChannelKeyChain(channel)['privKey']);
                  let socialPubKey = this.crypto.aes.decryptHex(msgData['message'],whistle);
                  this.socialSharedWith.push(msgData['channelPubKey']);
                  console.log('Read Receipt Social From ',msgData['channelPubKey']);
                  this.commit();
                }
                catch(error){
                  //fail silently
                  console.log(error);
                }

            }
        });



    }


    isInFavoriteRequestList(pubKey){
      for(let f of this.incomingFavoriteRequestList){
        if(f['pubKey'] == pubKey){
          return true;
        }
      }
      return false;
    }


    setSocialProfiles(v){
      this.socialProfiles = v;
    }
    setSocialProfile(profileId,v){
        this.socialProfiles[profileId] = v;
    }
    getSocialProfiles(){
      return this.socialProfiles;
    }
    setSocialLinks(v){
      this.socialLinks = v;
    }
    getSocialLinks(){
      return this.socialLinks;
    }
    setSocialSharedWith(array){
      this.socialSharedWith = array;
    }
    getSocialSharedWith(){
      return this.socialSharedWith;
    }
    clearSocialSharedWith(){
      this.socialSharedWith = [];
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
        if(pubObj['type'] == 'CHANNEL_MESSAGE' || pubObj['type'] == "SHARE_PUBLIC_SOCIAL"){
          //encrypt message
          this.DEVMODE && console.log('Encrypting CHANNEL_MESSAGE...');
          let {secret, aesEncryptedB64 } = this.crypto.aes.encrypt(pubObj['message'],this.getChannelKeyChain(pubObj['channel'])['pubKey']);
          pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        else if(pubObj['type'] == 'CHALLENGE_RESPONSE'){
          //encrypt response
          this.DEVMODE && console.log('Encrypting CHALLENGE_RESPONSE...');
          //add fields to response
          pubObj['response']['pubKey'] = this.getChannelKeyChain(pubObj['channel'])['pubKey'];
          let {secret, aesEncryptedB64 } = this.crypto.aes.encryptUtf8(JSON.stringify(pubObj['response']));
          pubObj['whistle'] = await this.crypto.rsa.fullEncrypt(secret,this.getOwnerPubKey(pubObj['channel']));
          pubObj['response'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        else if(pubObj['type'] == 'PRIVATE_MESSAGE' || pubObj['type'] == 'ownerSayHi' || pubObj['type'] == "SHARE_PRIVATE_SOCIAL" || pubObj['type'] == "RECEIVED_SOCIAL" || pubObj['type'] == "REQUEST_FAVORITE"){
          //encrypt response
          this.DEVMODE && console.log('Encrypting PRIVATE_MESSAGE...');
          let {secret, aesEncryptedB64 } = this.crypto.aes.encrypt(pubObj['message']);
          pubObj['whistle'] = await this.crypto.rsa.fullEncrypt(secret,this.getPubKeyFromChannelPubKey(pubObj['channel'],pubObj['toChannelPubKey']));
          pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
        }
        let date = new Date();
        pubObj['timestamp'] = date.getTime();
        pubObj['channelPubKey'] = this.getChannelKeyChain(pubObj['channel'])['channelPubKey'];
        pubObj = await this.sign(pubObj);

        // console.log('Signed Message Object:',pubObj);
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

      if(this.inviteCodes[channel]['links'].length > 10){
        this.inviteCodes[channel]['codes'] = {};
        this.inviteCodes[channel]['links'] = []
        this.inviteCodes[channel]['items'] = [];
      }

      this.inviteCodes[channel]['codes'][link] = code ;

      let links =  Object.keys(this.inviteCodes[channel]['codes']);
      let linkBuf = [];
      for(let thisLink of links){
        if(linkBuf.indexOf(thisLink) === -1){
          linkBuf.push(thisLink);
        }
      }

      if(this.inviteCodes[channel]['links'].indexOf(link) === -1 && linkBuf.indexOf(link) > -1){
        this.inviteCodes[channel]['links'].push(  link  );
        this.inviteCodes[channel]['items'].push({ max: newInviteCodeMax, used: 0, link: link, code:  code});
      }

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
