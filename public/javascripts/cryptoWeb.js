/**
 * Created by irkalla on 28.09.16.
 */
angular.module('App').controller('cryptoController', ['$scope', '$http',function($scope, $http) {



    function convertToHex(str) {
        var hex = '';
        for (var i = 0; i < str.length; i++) {
            hex += '' + str.charCodeAt(i).toString(16);
        }
        return hex;
    }

    function hexToAscii(hexx) {
        var hex = hexx.toString();//force conversion
        var str = '';
        for (var i = 0; i < hex.length; i += 2)
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        return str;
    }

    function encryptPubKeyRemote(m,e,n){
        console.log('Encrypt with remote PubKey');
        return m.modPow(e,n);
    }

    function decryptPubKeyRemote (signed,e,n){
        return signed.modPow(e,n);
    }

    function blindMsg (message,random,e,n){
      return  (message.multiply(random.modPow(e,n))).mod(n);
    }


    $scope.sendEncrypted = function(){
        $scope.sent = false;
        $http.get('http://localhost:3000/crypto/certificate').success(function(response){
            var msgHex = convertToHex($scope.data.secret);
            console.log('Secreto en HEX: '+msgHex);
            var msgToInt = bigInt(msgHex,16);
            console.log('Secreto en Int: '+msgToInt)

            console.log('N from server: ' + response.publicKey.n);

            var n = response.publicKey.n;
            console.log('PubKey n: '+ n);

            var e = response.publicKey.e;
            console.log('PubKey e: '+ e);
            console.log('PubKey bits: '+response.publicKey.bits);


            var encryptedMsg = encryptPubKeyRemote(msgToInt, e, n);
            console.log('Msg encrypted: '+ encryptedMsg);
            var encrString = encryptedMsg.toString(16);
            console.log('Cifrado to string: '+encrString);

            $http.post('http://localhost:3000/crypto/decrypt', {info:encrString}).success(function(response){
                $scope.sent = true;
                console.log('OK');

            });


        });
    };

    $scope.sendChallenge = function(){

        var chMD5 = CryptoJS.MD5($scope.data.challenge);
        console.log(chMD5.toString());

        $http.post('http://localhost:3000/crypto/sign', {challenge:chMD5.toString()}).success(function(response){
            console.log(response);
            var signedToInt = bigInt(response.signed16,16);
            console.log(signedToInt);

            var n = response.publicKey.n;
            console.log('PubKey n: '+ n);
            var e = response.publicKey.e;
            console.log('PubKey e: '+ e);
            console.log(bigInt(response.signed));
            var decrypt = hexToAscii(decryptPubKeyRemote(signedToInt,e,n).toString(16));

            console.log('Hash: '+decrypt);
            if(angular.equals(decrypt,chMD5.toString())){
                $scope.resultFAIL=false;
                $scope.resultOK = true;
                $scope.hash = decrypt;
                $scope.cert = response.info;
            }else{
                $scope.resultOK = false;
                $scope.resultFAIL=true;
            }


            console.log('OK');

        });
    };

    $scope.sendBlind = function(){
        $http.get('http://localhost:3000/crypto/certificate').success(function(response){
            var blindm = bigInt(convertToHex($scope.data.blind),16);
            console.log('Message to HEX: '+convertToHex($scope.data.blind));
            console.log('Message to BigInt: '+blindm);

            var n = response.publicKey.n;
            console.log('PubKey n: '+ n);

            var e = response.publicKey.e;
            console.log('PubKey e: '+ e);
            console.log('PubKey bits: '+response.publicKey.bits);

            var rand = bigInt.randBetween(0, n);
            console.log('Rand number: '+rand);
            var blindMessage = blindMsg(blindm,rand,e,n);

            console.log('Blind encrypted: '+ blindMessage);
            var encrBMsg = blindMessage.toString(16);
            console.log('Blind encrypted to string: '+encrBMsg);

            $http.post('http://localhost:3000/crypto/blind', {blind:encrBMsg}).success(function(response){
                var signedBlindInt = bigInt(response.signed16, 16);
                console.log(response.signed16);

                //var msgsign = signedBlindInt.multiply(rand.modInverse(n)).mod(n);
                var msgsign = (signedBlindInt.multiply(rand.modInv(n))).mod(n);
                $scope.blindSigned = msgsign.toString(16);
                console.log('MSG EN HEX: '+msgsign.toString(16));
                var verify = decryptPubKeyRemote(msgsign,e,n);
                var verifytohex = verify.toString(16);
                var verifyascii = hexToAscii(verifytohex);
                console.log(verifyascii);
                $scope.blindAscii = verifyascii;
                $scope.verifiedBlind=true;
                console.log('OK');

            });


        });



    };

    $scope.sendProtocol5 = function(){

        var keys = rsa2.generateKeys(256);

        var K = '54321';
        var secret = 'Hiroshima will be destroyed.';
        var crypto = CryptoJS.AES.encrypt(secret,K);
        var src = 'A';
        var dst = 'B';
        var line = '-';
        var concatenated = src.concat(line,dst,line,crypto);
        console.log(concatenated);
        var hash = CryptoJS.MD5(concatenated);
        var hashBig = bigInt(hash.toString(),16);
        console.log(hashBig.toString(16));
        var proofOrigin = keys.privateKey.encrypt(hashBig);
        console.log(proofOrigin.toString(16));
        console.log(hash.toString());

        var data ={publickey:{n:keys.publicKey.n.toString(16),e:keys.publicKey.e.toString(16)},src:src,dst:dst,crypto:crypto.toString(),proofOrigin:proofOrigin.toString(16)};

        console.log(data);

        console.log('##########SENDING MESSAGE TO B...##########');
        $http.post('http://localhost:3000/crypto/protocol5', {data:data}).success(function(response){
            console.log('##########RECEIVING RESPONSE FROM B...##########');
            console.log(response);


            //----------------
            var K = '54321';
            var src = 'A';
            var dst = 'B';
            var ttp = 'TTP';
            var line = '-';
            var concatenated = src.concat(line,ttp,line,dst,line,K);
            var hash = CryptoJS.MD5(concatenated);
            var hashBig = bigInt(hash.toString(),16);
            var proofOrigin = keys.privateKey.encrypt(hashBig);
            console.log('##########SENDING MESSAGE TO TTP...##########');
            var data ={publickey:{n:keys.publicKey.n.toString(16),e:keys.publicKey.e.toString(16)},src:src,dst:dst,ttp:ttp,proofOrigin:proofOrigin.toString(16),k:K};

            $http.post('http://localhost:3001/crypto/protocol5', {data:data}).success(function(response){

                console.log(response);


            });


        });
    };

    $scope.sendPaillier = function(){
        //Sends two encryptes numbers, the servers sum them up and returns the result.
        var keys = paillier.generateKeys(128);
        console.log(keys);

        var num1 = 13;
        var num2 = 33;

        //Example local
        var plainSum = num1+num2;

        console.log('-------------ADD-------------');
        console.log('PLAIN SUM: '+plainSum);


        var enc1 = keys.pub.encrypt(new BigInteger(num1.toString()).mod(keys.pub.n));
        var enc2 = keys.pub.encrypt(new BigInteger(num2.toString()).mod(keys.pub.n));


        var encryptedSum = keys.pub.add(enc1,enc2);
        console.log("ENCRYPTED SUM: " + encryptedSum);
        var sum = keys.sec.decrypt(encryptedSum);
        console.log("DECRYPTED SUM: " + sum);

        console.log('-------------MULT-------------');
        var plainMult = num1*num2;
        console.log('PLAIN SUM: '+plainMult);
        var encryptedMult = keys.pub.mult(enc1, new BigInteger(num2.toString()));
        console.log("ENCRYPTED MULT: " + encryptedMult);
        var mult = keys.sec.decrypt(encryptedMult);
        console.log("DECRYPTED MULT: " + mult);

        //Example remote
        var data=
        {
            num1:enc1.toString(),
            num2:enc2.toString(),
            n2:keys.pub.n2.toString()
        };
        console.log(data);
/*
        $http.post('/operaciones/sumar',data)
            .success(function (data)
            {
                console.log("Intento mostrar la suma encriptada: " +  data);
                var encriptedSum2 = new BigInteger(data.toString());
                console.log("Intento mostrar la suma encriptada: " +  encriptedSum2);
                var decripsuma = keys.sec.decrypt(encriptedSum2);
                console.log("Intento mostrar la suma desencriptada: " + decripsuma);
                $scope.resultado3 = 'correcto';
                document.getElementById("resultadoSuma").innerHTML = (decripsuma);
            })
            .error(function (data) {
                $scope.resultado3 = 'incorrecto';
                console.log('Error: ' + data)
            });
        */
    };

    $scope.sharedSecret = function(){
       // var key = secrets.random(512);
        var secret = 'Bin Laden is alive';
        // convert the text into a hex string
        var secretHex = secrets.str2hex(secret); // => hex string

        console.log('Split into 5 shares, with a threshold of 3');
        var sharedsecret = secrets.share(secretHex, 5, 3);

        console.log('The 5 shares:');
        console.log(sharedsecret[0]);
        console.log(sharedsecret[1]);
        console.log(sharedsecret[2]);
        console.log(sharedsecret[3]);
        console.log(sharedsecret[4]);

        console.log('Combining 3 of them....');
        // combine 3 shares:
        var comb = secrets.combine( [ sharedsecret[1], sharedsecret[3], sharedsecret[4] ] );

        //convert back to UTF string:
        var  combString = secrets.hex2str(comb);
        console.log('SECRET: <<<<<<<<<<< '+combString+' >>>>>>>>>>');






    };
































}]);








