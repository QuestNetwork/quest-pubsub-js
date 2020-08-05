# Quest PubSub JS

## Lead Maintainer

[StationedInTheField](https://github.com/StationedInTheField)

## Please Donate
This project is a lot of work and unfortunately we have to eat and pay rent, we'd be thrilled if you could send us a small donation to:

Bitcoin:
`bc1qujrqa3s34r5h0exgmmcuf8ejhyydm8wwja4fmq`

Ethereum:
`0xBC2A050E7B87610Bc29657e7e7901DdBA6f2D34E`

## Description

The JavaSript implementation of the QuestNetwork PubSub Protocol.

## Warning

NPM doesn't work for Quest Network Swarm Projects, because they have to load data from a swarm info file at the build step,
which needs to be provided locally for security reasons. Instead copy or symlink the main folder to your swarm app or package on
the build step and define the dependency as local.

If you feel like you really really need to, you can `npm run start`, which will compile and run thee test.js file.

## Installation & Usage

Please use our [quest-cli](https://github.com/QuestNetwork/quest-cli) to test and build the package.

Pro Tip: Put a file in your `/bin` that runs the quest-cli like so `node /path/to/quest-cli/index.js` from any folder on your system. It's much nicer!
