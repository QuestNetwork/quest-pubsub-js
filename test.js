import { PubSub } from './pubsub.js';
export { PubSub as ChannelPubSub };
export let GlobalPubSub = new PubSub();


async function test(){
  let channel = await GlobalPubSub.createChannel('test');
  console.log(channel);
  console.log(GlobalPubSub.getChannelKeyChain(channel));
  let {secret, aesEncryptedB64 } = GlobalPubSub.aesEncryptUtf8("Test Message",GlobalPubSub.getChannelKeyChain(channel)['pubKey']);
  let pubObj = {};
  // console.log(aesEncryptedB64);
  pubObj['message'] = Buffer.from(aesEncryptedB64,'base64');
  let date = new Date();
  pubObj['timestamp'] =  date.getTime();
  pubObj['channelPubKey'] = GlobalPubSub.getChannelKeyChain(channel)['channelPubKey'];
  pubObj = GlobalPubSub.sign(pubObj);
  let dataString = JSON.stringify(pubObj);
  let data = Buffer.from(dataString,'utf8');

  let msgData = JSON.parse(data.toString('utf8'));
  let signatureVerified = await GlobalPubSub.verify(msgData);
  if(msgData['type'] == 'channelMessage' && GlobalPubSub.isParticipant(GlobalPubSub.channelParticipants[channel]['cList'], msgData['channelPubKey']) && signatureVerified){
   console.log('got message from ' + message.from)
   //decrypt this message with the users public key
   let msg = {};
   msg['message'] = GlobalPubSub.aesDecryptB64(msgData['message'].toString('base64'),GlobalPubSub.channelParticipantList['pList'].split(',')[GlobalPubSub.channelParticipantList['cList'].split(',').indexOf(msgData['channelPubKey'])]);
   msg['type'] = "channelMessage";
   msg['from'] = message.from;
   console.log(msg);
  }

}

test();
