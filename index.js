export class PubSub {
  constructor(name) {
    this.name = name;
  }
  ipfsCID;
  subs;
  createChannel(channelInput){
    //generate keypair
    let channelKeyChain = this.generateChannelKeyChain();
    let democracy = "rep";
    let channel = channelInput+"-|-"+channelKeyChain['channelPubKey']+"-|-"+democracy;
    addToKeyChain(channel, channelKeyChain);
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

  channelParticipantList;
  getChannelParticipants(channel){
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


  generateChannelKeyChain(){
    let keyPair = WebCrypto.subtle.generateKey({
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




  sign(obj){
    let string = JSON.stringify(Obj);
    let encoded = new TextEncoder();
    return await window.crypto.subtle.sign(
     {
       name: "ECDSA",
       hash: {name: "SHA-512"},
     },
     this.getChannelKeyChain(obj['channel'])['channelPrivKey'],
     encoded
    );
  }

  verify(obj, publicKey){
    let sig = obj['sig'];
    //remove
    delete obj['sig'];
    let enc = new TextEncoder();
    let encoded enc(JSON.stringify(obj));
    return await window.crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: {name: "SHA-512"},
      },
      publicKey,
      sig,
      encoded
    );
  }
  keyChain;


  setChannelKeyChain(keychain, channel = "all"){
    if(channel == "all"){
        this.channelKeyChain = keychain;
    }
    else{
      this.channelKeyChain[channel] = keychain;
    }
  }


  getChannelKeyChain(channel){
    return this.keyChain[channel];
  }



  joinChannel(transport,channel,ipfsCID){
    return new Promise( async (resolve) => {
      this.ipfsCID = ipfsCID;
      // TODO: if channel doesn't exist create it first and become owner?

      let date = new Date();
      let timestamp = date.time();

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
        let pubObj = { fromCID: this.ipfsCID, channel: channel, type: "sayHi", channelPubKey: channelKeyChain['channelPubKey'], timestamp: timestamp };
        pubObj['sig'] = this.sign(channel,pubObj);
        transport.publish(pubObj);
      }
      else{
        //  TODOO  this.publish({ type: "opaqueSayHi", to: message.from, QuestPubSub.ownerSayHi({ toCID: message.from, toWhistleID: data['whistleID'], toTime: timestamp, channelParticipantList: this.channelParticipantList[channel], this.channelKeyChain[channel]['pubKey'] ) });
      }

      this.subs[channel] = new Subject();
      transport.subscribe(channel, (message) => {
          let data = JSON.parse(message.data.toString());
          if(iamowner && data['type'] == 'sayHi' || (data['type'] == 'CHALLENGE_RESPONSE' && data['toCID'] == this.ipfsCID){
            //user has completed the challenge, maybe we will add them to the channel
            if(data['type'] == 'CHALLENGE_RESPONSE'){
              let challengeMastered = this.testEncryptedChallengeResponse(data['response']);
              if(!challengeMastered){
                throw('bad challenge response');
              }
            }

            //put together a message with all users whistleid timestamp, hash and sign message with pubkey
            let { cList, pList } = await this.getChannelParticipants(channel);
            if(this.isParticipant(cList, data['whistleID']){
              this.publish({ type: "ownerSayHi", toCID: message.from, this.ownerSayHi({ toCID: message.from, toChannelPubKey: data['channelPubKey'], timestamp: timestamp, channelParticipantList: this.channelParticipantList[channel], this.channelKeyChain[channel]['pubKey'] ) });
            }
            else{
              //this is a new guy, maybe we should add them to the list? let's challenge them! you should customize this function!!!
              this.publish({ type: "CHALLENGE", toCID: message.from, this.challenge({ toCID: message.from, toChannelPubKey: data['channelPubKey'], timestamp: timestamp, channelParticipantList: this.channelParticipantList[channel], this.channelKeyChain[channel]['pubKey'] ) });
            }
          }
          else if(data['type'] == 'CHALLENGE' && data['toCID'] == this.ipfsCID){
            //show captcha screen for user
            resolve({action: 'CHALLENGE', timestamp: data['timestamp'] fromCID: message.from, encryptedPubKey: encryptedPubKey});
            //owner is challenging us to join, we will complete the challenge and encrypt our public key for the owner with their publickey
          }
          else if(data['type'] == 'ownerSayHi'){
          //WE RECEIVED A USER LIST
          try{
              this.setChannelParticipantList(channel,  this.parseParticipantList(channel, data['message']));;
              resolve({action: "APPROVED"});
            }
            catch(err){
              throw('bad list');
            }
          }
          else if(data['type'] == 'channelMessage' && this.isParticipant(this.channelParticipants[channel]['cList'], data['whistleID'])){
            console.log('got message from ' + message.from)

            //decrypt this message with the users public key
            let encrypted =  data['message'];
            let decrypted = encrypted;

            let msg = {};
            msg['message'] = decrypted;
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
        let message = "RSA PRIVATE KEY ENCRYPTED MESSAGE";

      }

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

  ownerSayHi(pubObj){
    //pubObj = { toCID: message.from, toWhistleID: data['whistleID'], toTime: timestamp, channelParticipantList: this.channelParticipantList[channel], this.channelKeyChain[channel]['pubKey'] }
    return sayHiResponse;
  }

  challenge(){

  }

  masterChallenge(){

  }






}
