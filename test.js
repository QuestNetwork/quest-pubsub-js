import { PubSub } from './pubsub.js';
export { PubSub as ChannelPubSub };
export let GlobalPubSub = new PubSub();


async function publicChannelMessage(testMessage){
  let channel = await GlobalPubSub.createChannel('test');
  console.log('channel:',channel);
  // console.log(GlobalPubSub.getChannelKeyChain(channel));
  // console.log('whistle:');
  // console.log(GlobalPubSub.getChannelKeyChain(channel)['pubKey']);
  let {secret, aesEncryptedB64 } = GlobalPubSub.aesEncryptUtf8(testMessage,GlobalPubSub.getChannelKeyChain(channel)['pubKey']);
  let pubObj = {};
  // console.log(aesEncryptedB64);
  pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
  let date = new Date();
  pubObj['channel'] = channel;
  pubObj['type'] = "CHANNEL_MESSAGE";
  pubObj['timestamp'] =  date.getTime();
  pubObj['channelPubKey'] = GlobalPubSub.getChannelKeyChain(channel)['channelPubKey'];
  // console.log(GlobalPubSub.getChannelKeyChain(channel));

  pubObj = await GlobalPubSub.sign(pubObj);
  let dataString = JSON.stringify(pubObj);
  let data = Buffer.from(dataString,'utf8');
  let msgData = JSON.parse(data.toString('utf8'));
  let signatureVerified = await GlobalPubSub.verify(msgData);
  // console.log(signatureVerified);
  if(msgData['type'] == 'CHANNEL_MESSAGE' && GlobalPubSub.isParticipant(GlobalPubSub.getChannelParticipantList([channel])['cList'], msgData['channelPubKey']) && signatureVerified){
   // console.log('got message from ' + msgData['channelPubKey'])
   //decrypt this message with the users public key
   let msg = {};
   let whistleArray = GlobalPubSub.getChannelParticipantList(msgData['channel'])['pList'].split(',');
   let whistleIndex = GlobalPubSub.getChannelParticipantList(msgData['channel'])['cList'].split(',').indexOf(msgData['channelPubKey']);
   let whistle = whistleArray[whistleIndex];
   // console.log('whistle:');
   // console.log(whistle);
   let msgB64 = Buffer.from(msgData['message'],'hex').toString('base64');
   // console.log(msgB64);
   msg['message'] = GlobalPubSub.aesDecryptB64(msgB64,whistle);
   msg['type'] = "CHANNEL_MESSAGE";
   if(msg['message'] == testMessage){
     console.log('channel messages work!');
   }
   else{
     console.log('channel messages broken!');
   }
  }
}


async function privateChannelMessage(testMessage){
  let channel = await GlobalPubSub.createChannel('test');
  console.log('channel');
  console.log(channel);
  // console.log(GlobalPubSub.getChannelKeyChain(channel));
  // console.log('whistle:');
  // console.log(GlobalPubSub.getChannelKeyChain(channel)['pubKey']);
  let {secret, aesEncryptedB64 } = GlobalPubSub.aesEncryptUtf8(testMessage);
  let pubObj = {};
  console.log(secret);
  // console.log(aesEncryptedB64);

  pubObj['whistle'] = await GlobalPubSub.rsaFullEncrypt(secret,GlobalPubSub.getChannelKeyChain(channel)['pubKey']);
  console.log(pubObj['whistle']);
  // console.log('here!!!!!');
  // console.log('here!!!!!');
  // console.log('here!!!!!');
  // console.log('here!!!!!');
  //
  pubObj['message'] = Buffer.from(aesEncryptedB64,'base64').toString('hex');
  let date = new Date();
  pubObj['channel'] = channel;
  pubObj['type'] = "CHANNEL_MESSAGE";
  pubObj['timestamp'] =  date.getTime();
  pubObj['channelPubKey'] = GlobalPubSub.getChannelKeyChain(channel)['channelPubKey'];
  // console.log(GlobalPubSub.getChannelKeyChain(channel));

  pubObj = await GlobalPubSub.sign(pubObj);
  let dataString = JSON.stringify(pubObj);
  let data = Buffer.from(dataString,'utf8');
  let msgData = JSON.parse(data.toString('utf8'));
  let signatureVerified = await GlobalPubSub.verify(msgData);
  console.log(signatureVerified);
  if(msgData['type'] == 'CHANNEL_MESSAGE' && GlobalPubSub.isParticipant(GlobalPubSub.getChannelParticipantList([channel])['cList'], msgData['channelPubKey']) && signatureVerified){
   // console.log('got message from ' + msgData['channelPubKey'])
   //decrypt this message with the users public key
   let msg = {};

  console.log(msgData['whistle']);
   // let whistleArray = GlobalPubSub.getChannelParticipantList(msgData['channel'])['pList'].split(',');
   // let whistleIndex = GlobalPubSub.getChannelParticipantList(msgData['channel'])['cList'].split(',').indexOf(msgData['channelPubKey']);
   // let whistle = whistleArray[whistleIndex];
  //  // console.log('whistle:');
  //  // console.log(whistle);
   let msgB64 = Buffer.from(msgData['message'],'hex').toString('base64');
   msgData['whistle'] = await GlobalPubSub.rsaFullDecrypt(msgData['whistle'],GlobalPubSub.getChannelKeyChain(channel)['privKey']);
   msg['message'] = GlobalPubSub.aesDecryptB64(msgB64,msgData['whistle']);
   msg['type'] = "CHANNEL_MESSAGE";
   if(msg['message'] == testMessage){
     console.log('private messages work!');
   }
   else{
     console.log('private messages broken!');
   }
  
  }

}

async function test(){
  await publicChannelMessage("Testing This!");
  await privateChannelMessage("Testing This!");
}

test();
