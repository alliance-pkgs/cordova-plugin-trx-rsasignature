function RSASignature() {
}

RSASignature.prototype.getPublicKey = function (successCallback, errorCallback) {
  cordova.exec(
    successCallback,
    errorCallback,
    "RSASignature",
    "getPublicKey",
    [{}]
  );
};

RSASignature.prototype.getTrxSignature = function ( params, successCallback, errorCallback) {
  cordova.exec(
    successCallback,
    errorCallback,
    "RSASignature",
    "getTrxSignature",
    [params]
  );
};

module.exports = new RSASignature();