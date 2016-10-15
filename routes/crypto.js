/**
 * Created by irkalla on 19.09.16.
 */

var express = require('express');
var router = express.Router();
var rsa = require('./rsa-bignum');
var bignum = require('bignum');
var CryptoJS = require('crypto-js');

var keys = rsa.generateKeys(512);
var crypto;

function decryptPubKeyRemote (signed,e,n){
    return signed.powm(e,n);
}


//POST-Receives a message and DECRYPTS it. Then it is sent to the client again.
router.post('/decrypt',function(req,res){
        console.log('Encrypted from client: '+req.body.info);
        var msgEncrypted = req.body.info;
        var msgDesBNum = keys.privateKey.decrypt(bignum(msgEncrypted,16));
        console.log('Decrypted BigNum: '+msgDesBNum);
        var msgPlaintText = msgDesBNum.toBuffer().toString();

        console.log('SECRET MESSAGE: '+msgPlaintText);

        res.send({info:'OK'});

        });


//GET-Sends the certificate (PubKey and Info) to the client
router.get('/certificate',function(req,res){
    console.log('GET');
    var publicK = keys.publicKey;
    var publicKey = {n:publicK.n.toString(), e:publicK.e.toString(),bits:publicK.bits};

    var packPK = keys.publicKey;

    console.log('GET PUBLIC KEY PACK:', packPK.bits);
    res.send({publicKey:publicKey,info:'Test Certificate'});

}) ;

//SIGN->POST-Given a challenge(MD5 encoded), the server signs it with the PrivateKey and sends it back.
router.post('/sign',function(req,res){
    console.log('Signing challenge....');

    console.log('Challenge: '+req.body.challenge);
    var chToBigInt = bignum.fromBuffer(new Buffer(req.body.challenge));
    console.log('Challenge BInt: '+chToBigInt);
    var challengeSigned = keys.privateKey.sign(chToBigInt);
    console.log('Challenge signed: '+challengeSigned.toString(16));
    var publicK = keys.publicKey;
    var publicKey = {n:publicK.n.toString(), e:publicK.e.toString(),bits:publicK.bits};
    res.status(200).send({publicKey:publicKey,info:'Server x.509 Certificate',signed:challengeSigned.toString(),signed16:challengeSigned.toString(16)});


});

//SIGN - BLIND message
router.post('/blind',function(req,res){
    console.log('Signing blind message....');

    console.log('Blind: '+req.body.blind);
    var chToBigInt = bignum(req.body.blind,16);
    console.log('Blind BInt: '+chToBigInt);
    var challengeSigned = keys.privateKey.sign(chToBigInt);
    console.log('Blind signed: '+challengeSigned.toString(16));
    var publicK = keys.publicKey;
    var publicKey = {n:publicK.n.toString(), e:publicK.e.toString(),bits:publicK.bits};
    res.status(200).send({publicKey:publicKey,info:'Server x.509 Certificate',signed:challengeSigned.toString(),signed16:challengeSigned.toString(16)});


});

//PROTOCOL 5 A-B,B-A
router.post('/protocol5',function(req,res){
    console.log('Encrypted from client: '+req.body);

    console.log('##########RECEIVING MESSAGE FROM A...##########')
    var src = req.body.data.src;
    var dst = req.body.data.dst;
    crypto = req.body.data.crypto;
    var proofOrigin = req.body.data.proofOrigin;
    var pubkA_n = req.body.data.publickey.n;
    var pubkA_e = req.body.data.publickey.e;
    console.log(req.body.data.publickey.n);
    console.log(req.body.data.publickey.e);

    var pO = bignum(proofOrigin,16);
    var pk_n_BG = bignum(pubkA_n,16);
    var pk_e_BG = bignum(pubkA_e,16);
    var decryptSignature = decryptPubKeyRemote(pO,pk_e_BG,pk_n_BG);
    console.log(decryptSignature);
    var hashFromServer = decryptSignature.toString(16);
    console.log('PROOF SERVER: '+hashFromServer);
    var concat = src.concat('-',dst,'-',crypto);
    var hashToCompare = CryptoJS.MD5(concat);
    console.log('HASH TO COMPARE: '+hashToCompare);
    if(hashFromServer == hashToCompare)
        {
            console.log('HASHES MATCH!!!');
        }

    var concatenated = 'B'+'A'+crypto;
    var hasHH = CryptoJS.MD5(concatenated);
    var hashToClient = bignum(hasHH.toString(),16);
    var proofOriginS = keys.privateKey.encrypt(hashToClient);



    res.status(200).send({src:'B',dst:'A',proofOrigin:proofOriginS.toString(16)});


});


//PROTOCOL 5 TTP-B
router.post('/protocol5_ttp',function(req,res){
    console.log('Message TTP: '+req.body);

    console.log('##########RECEIVING MESSAGE KEY FROM TTP ...##########');
    var key = req.body.k;
    var secretMessage  = CryptoJS.AES.decrypt(crypto.toString(), key);
    var plaintext = secretMessage.toString(CryptoJS.enc.Utf8);
    console.log('SECRET MESSAGE: ###########################   '+plaintext+'   ###############################')

});

router.post('/paillier',function(req,res){
    var x = paillierKeys.publicKey.n;

});





module.exports = router;