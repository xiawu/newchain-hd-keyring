const EventEmitter = require('events').EventEmitter
const hdkey = require('ethereumjs-wallet/hdkey')
const bip39 = require('bip39')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')

// Options:
const hdPathString = `m/44'/60'/0'/0`
const type = 'HD Key Tree'


const elliptic = require('elliptic')
const hash = require('hash.js')
var BN = require('bn.js');

class HdKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor (opts = {}) {
    super()
    this.type = type
    this.deserialize(opts)
  }

  serialize () {
    return Promise.resolve({
      mnemonic: this.mnemonic,
      numberOfAccounts: this.wallets.length,
      hdPath: this.hdPath,
    })
  }

  deserialize (opts = {}) {
    this.opts = opts || {}
    this.wallets = []
    this.appKeys = []    
    this.mnemonic = null
    this.root = null
    this.hdPath = opts.hdPath || hdPathString

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic)
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts)
    }

    return Promise.resolve([])
  }



  
  addAccounts (numberOfAccounts = 1) {
    if (!this.root) {
      this._initFromMnemonic(bip39.generateMnemonic())
    }

    const oldLen = this.wallets.length
    const newWallets = []
    for (let i = oldLen; i < numberOfAccounts + oldLen; i++) {
      const child = this.root.deriveChild(i)
      const wallet = child.getWallet()
      newWallets.push(wallet)
      this.wallets.push(wallet)
    }
    const hexWallets = newWallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    })
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map((w) => {
      return sigUtil.normalize(w.getAddress().toString('hex'))
    }))
  }

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction (address, tx) {
    const wallet = this._getWalletForAccount(address)
    var privKey = wallet.getPrivateKey()
    tx.sign(privKey)
    return Promise.resolve(tx)
  }

  // For eth_sign, we need to sign transactions:
  // hd
  signMessage (withAccount, data) {
    const wallet = this._getWalletForAccount(withAccount)
    const message = ethUtil.stripHexPrefix(data)
    var privKey = wallet.getPrivateKey()
    var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
    var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.stripHexPrefix(wallet.getPrivateKey())
    const privKeyBuffer = new Buffer(privKey, 'hex')
    const sig = sigUtil.personalSign(privKeyBuffer, { data: msgHex })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
    const signature = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(signature)
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = wallet.getPrivateKey()
    const msgBuffer = ethUtil.toBuffer(msgHex)
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer)
    const msgSig = ethUtil.ecsign(msgHash, privKey)
    const rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  exportAccount (address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }


  /* PRIVATE METHODS */

  _initFromMnemonic (mnemonic) {
    this.mnemonic = mnemonic
    const seed = bip39.mnemonicToSeed(mnemonic)
    this.hdWallet = hdkey.fromMasterSeed(seed)
    this.root = this.hdWallet.derivePath(this.hdPath)
  }


  _getWalletForAccount (account) {
    const targetAddress = sigUtil.normalize(account)
    return this.wallets.find((w) => {
      const address = sigUtil.normalize(w.getAddress().toString('hex'))
      return ((address === targetAddress) ||
              (sigUtil.normalize(address) === targetAddress))
    })
  }


  /* APP KEYS */

  // private
  _appKey_ecc_createKeyPair(hdPath) {
    if (!this.root) {
      this._initFromMnemonic(bip39.generateMnemonic())
    }
    console.log("full hdPath", hdPath)
    const child = this.hdWallet.derivePath(hdPath)
    console.log("debug child", child)
    const keyPair = child.getWallet()
    const hexKey = sigUtil.normalize(keyPair.getAddress().toString('hex'))
    const appKey = {hdPath,
		    keyPair,
		    address: hexKey}
    this.appKeys.push(appKey)
    return Promise.resolve(keyPair)
  }

  // private
  _appKey_ecc_getKeyPair(hdPath) {
    const previouslyCreated = this.appKeys.filter((appKey) => appKey.hdPath === hdPath)
    if (previouslyCreated[0]) {
      console.log(previouslyCreated[0])
      return Promise.resolve(previouslyCreated[0].keyPair)
    }
    const keyPair = this._appKey_ecc_createKeyPair(hdPath)    
    return Promise.resolve(keyPair)
  }
  // _appKey_ec_getKeyPairByAddress (address) {
  //   const targetAddress = sigUtil.normalize(address)
  //   return this.appKeys.find((w) => {
  //     address = sigUtil.normalize(w.address.toString('hex'))
  //     return ((address === targetAddress) ||
  //             (sigUtil.normalize(address) === targetAddress))
  //   }).keyPair
  // }
  
  async appKey_ecc_getPublicKey(hdPath) {
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    const pubKey = keyPair.getPublicKeyString()
    return Promise.resolve(pubKey)    
  }

  // eth methods:

  async appKey_eth_getPublicKey(hdPath) {
    return this.appKey_ecc_getPublicKey(hdPath)
  }

  async appKey_eth_getAddress(hdPath) {
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    const address = sigUtil.normalize(keyPair.getAddress().toString('hex'))
    return Promise.resolve(address)
  }

  // requires msg of length 64 chars hence 32 bytes, 256 bits
  async appKey_eth_signMessage (hdPath, message) {
    console.log("lenght of message: ", message.length)
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    var privKey = keyPair.getPrivateKey()
    message = ethUtil.stripHexPrefix(message)
    var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
    var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // tx is an instance of the ethereumjs-transaction class.
  async appKey_eth_signTransaction (hdPath, tx) {
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    var privKey = keyPair.getPrivateKey()
    tx.sign(privKey)
    return Promise.resolve(tx)
  }

  async appKey_eth_signTypedMessage (hdPath, typedData) {
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    const privKey = ethUtil.toBuffer(keyPair.getPrivateKey())
    const signature = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(signature)
  }

  // stark methods
  async appKey_stark_signMessage (hdPath, message) {
    const keyPair = await this._appKey_ecc_getKeyPair(hdPath)
    const privKey = ethUtil.toBuffer(keyPair.getPrivateKey())

    // test: with below privKey
    // signing "1e542e2da71b3f5d7b4e9d329b4d30ac0b5d6f266ebef7364bf61c39aac35d0" + "0"
    // gives r: "1408ea79096199916cbf2c7a5162aa8973704dbd325cdb4e7d9dcef4dc686f7"
    // and v: "5635c32072ffbb750006652e6185bd1d2fcbd71306ec500d103530d687139d3"
    
    // const privKey = new BN("3c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc", 16);
    
    var ec = new elliptic.ec(new elliptic.curves.PresetCurve({
      type: 'short',
      prime: null,
      p: '08000000 00000011 00000000 00000000 00000000 00000000 00000000 00000001',
      a: '00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001',
      b: '06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89',
      n: '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
      hash: hash.sha256,
      gRed: false,
      g: [
        '01ef15c1 8599971b 7beced41 5a40f0c7 deacfd9b 0d1819e0 3d723d8b c943cfca',
        '00566806 0aa49730 b7be4801 df46ec62 de53ecd1 1abe43a3 2873000c 36e8dc1f'
      ]
    }))
    var signature = ec.keyFromPrivate(privKey).sign(message)
    return Promise.resolve(signature)
  }
    
  
}

HdKeyring.type = type
module.exports = HdKeyring
