

export class PubSub {
  constructor(name) {
    this.name = name;
  }


  keyChain;
  channelParticipantList;

  addToKeyChain(channel, channelKeyChain){
    this.keyChain[channel] = channelKeyChain;
  }


  getChannelKeyChain(channel){
    return this.keyChain[channel];
  }

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

  isParticipant(list, whistleIDorKey){
    return ((list.indexOf(whistleIDorKey) > -1) ? true : false);
  }


  channelParticipantList = {};
  getChannelParticipants(topic){
    if(typeof(this.channelParticipantList[topic]['wList']) != 'undefined' && typeof(this.channelParticipantList[topic]['pList']) != 'undefined'){
      resolve(this.channelParticipantList[topic]);
    }
    throw('participants not saved');
  }

  setChannelParticipants(topic, participants){
    this.channelParticipantList[topic] = participants;
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

  ipfsCID;
  subs;


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


  joinChannel(transport,channel, whistleID, ipfsCID){
    return new Promise( async (resolve) => {
      this.ipfsCID = ipfsCID;
      // TODO: if channel doesn't exist create it first and become owner?

      let date = new Date();
      let timestamp = date.time();

      //Retrieve keys
      let channelKeyChain;
      if(typeof(this.keyChain[topic]) == 'undefined'){
          //generate keys for this channel
          channelKeyChain = this.generateChannelKeyChain();
          addToKeyChain(channel, channelKeyChain);
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
          //this.publish({ channel: topic, type: "opaqueSayHi", whistleID: this.whistle.getWhistleID(), timestamp });
        }
      }

      if(!amiowner){
        //we are going to announce our join, share our pubkey-chain and request the current participant list
        let pubObj = { fromCID: this.ipfsCID, channel: channel, type: "sayHi", whistleID: whistleID, timestamp: timestamp };
        pubObj['sig'] = this.sign(channel,pubObj);
        transport.publish(pubObj);
      }
      else{
        //  TODOO  this.publish({ type: "opaqueSayHi", to: message.from, QuestPubSub.ownerSayHi({ toCID: message.from, toWhistleID: data['whistleID'], toTime: timestamp, channelParticipantList: this.channelParticipantList[topic], this.channelKeyChain[topic]['pubKey'] ) });
      }

      this.subs[channel] = new Subject();
      transport.subscribe(topic, (message) => {
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
            let { wList, pList } = await this.getChannelParticipants(topic);
            if(this.isParticipant(wList, data['whistleID']){
              this.publish({ type: "ownerSayHi", toCID: message.from, this.ownerSayHi({ toCID: message.from, toWhistleID: data['whistleID'], timestamp: timestamp, channelParticipantList: this.channelParticipantList[topic], this.channelKeyChain[topic]['pubKey'] ) });
            }
            else{
              //this is a new guy, maybe we should add them to the list? let's challenge them! you should customize this function!!!
              this.publish({ type: "CHALLENGE", toCID: message.from, this.challenge({ toCID: message.from, toWhistleID: data['whistleID'], timestamp: timestamp, channelParticipantList: this.channelParticipantList[topic], this.channelKeyChain[topic]['pubKey'] ) });
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
              this.setChannelParticipants(topic,  this.parseParticipantList(topic, data['message']));;
              resolve({action: "APPROVED"});
            }
            catch(err){
              throw('bad list');
            }
          }
          else if(data['type'] == 'channelMessage' && this.isParticipant(this.channelParticipants[topic]['wList'], data['whistleID'])){
            console.log('got message from ' + message.from)

            //decrypt this message with the users public key
            let encrypted =  data['message'];
            let decrypted = encrypted;

            let msg = {};
            msg['message'] = decrypted;
            msg['type'] = "channelMessage";
            msg['from'] = message.from;
            this.subs[topic].next(msg);
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
    //pubObj = { toCID: message.from, toWhistleID: data['whistleID'], toTime: timestamp, channelParticipantList: this.channelParticipantList[topic], this.channelKeyChain[topic]['pubKey'] }
    return sayHiResponse;
  }

  challenge(){

  }

  masterChallenge(){

  }






}
