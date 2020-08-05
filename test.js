import { PubSub } from './pubsub.js';
export { PubSub as ChannelPubSub };
export let GlobalPubSub = new PubSub();


async function test(){
  let test = await GlobalPubSub.createChannel('test');
  console.log(test);
}

test();
