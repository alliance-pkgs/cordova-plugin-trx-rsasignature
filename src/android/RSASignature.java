package com.cv.alliance.aop.trx;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

@TargetApi(23)
public class RSASignature extends CordovaPlugin {

    public static final String TAG = "RSASignature";
    public static String packageName;

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    /**
     * Alias for our key in the Android Key Store
     */
    public static final String KEY_NAME = "abmb_key";

    public static KeyStore mKeyStore;
    public static KeyPairGenerator mKeyGenerator;
    public static Signature mCipher;

    public static CallbackContext mCallbackContext;
    public static PluginResult mPluginResult;

    /**
     * Constructor.
     */
    public RSASignature() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        Log.v(TAG, "Init RSASignature");
        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);

        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }

        try {
            mKeyGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }

        try {
            mCipher = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        mCallbackContext = callbackContext;
        Log.v(TAG, "RSASignature action: " + action);
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error("minimum SDK version 23 required");
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        final JSONObject arg_object = args.getJSONObject(0);
        if (action.equals("getPublicKey")) {
            JSONObject resultJson = new JSONObject();
            PublicKey pubkey = getPublicKey();
            boolean isCipherInit = true;
            if (pubkey == null) {
                if (createKey()) {
                    pubkey = getPublicKey();
                }
            }
            if (pubkey != null && !initCipher()) {
                isCipherInit = false;
            }
            if (pubkey != null) {
                byte[] publicKeyBytes = pubkey.getEncoded();
                String pubKeyStr = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);
                resultJson.put("publicKey", pubKeyStr);
            }

            mPluginResult = new PluginResult(PluginResult.Status.OK, resultJson);
            mCallbackContext.success(resultJson);
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        } else if (action.equals("getTrxSignature")) {
            if (!arg_object.has("username")) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("Missing required parameters");
                mCallbackContext.sendPluginResult(mPluginResult);
                return true;
            }

            String username = arg_object.getString("username");
            String date = arg_object.getString("date");
            PrivateKey key = getSecretKey();
            boolean isCipherInit = true;
            if (key == null) {
                if (createKey()) {
                    key = getSecretKey();
                }
            }
            if (key != null && !initCipher()) {
                isCipherInit = false;
            }


            JSONObject resultJson = new JSONObject();
            String errorMessage = "";
            boolean createdResultJson = false;
            try {
                byte[] encrypted = signTransaction(username, date);
                resultJson.put("rsaSignature", Base64.encodeToString(encrypted, Base64.NO_WRAP /* flags */));

                createdResultJson = true;
            } catch (BadPaddingException e) {
                errorMessage = "Failed to encrypt the data with the generated key:" + " BadPaddingException:  "
                        + e.getMessage();
                Log.e(TAG, errorMessage);
            } catch (IllegalBlockSizeException e) {
                errorMessage = "Failed to encrypt the data with the generated key: " + "IllegalBlockSizeException: "
                        + e.getMessage();
                Log.e(TAG, errorMessage);
            } catch (JSONException e) {
                errorMessage = "Failed to set resultJson key value pair: " + e.getMessage();
                Log.e(TAG, errorMessage);
            }

            if (createdResultJson) {
                mCallbackContext.success(resultJson);
                mPluginResult = new PluginResult(PluginResult.Status.OK);
            } else {
                mCallbackContext.error(errorMessage);
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            }
            mCallbackContext.sendPluginResult(mPluginResult);

            return true;
        }
        return false;
    }

    private PublicKey getPublicKey() {
        try {
            mKeyStore.load(null);
            return mKeyStore.getCertificate(KEY_NAME).getPublicKey();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private PrivateKey getPrivateKey() {
        try {
            mKeyStore.load(null);
            return (PrivateKey) mKeyStore.getKey(KEY_NAME, null);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private static boolean initCipher() {
        boolean initCipher = false;
        String errorMessage = "";
        String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
        try {
            PrivateKey key = getSecretKey();
            mCipher.initSign(key);

            initCipher = true;
        } catch (InvalidKeyException e) {
            errorMessage = initCipherExceptionErrorPrefix + "InvalidKeyException: " + e.toString();
        }
        if (!initCipher) {
            Log.e(TAG, errorMessage);
        }
        return initCipher;
    }

    private static PrivateKey getSecretKey() {
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        PrivateKey key = null;
        try {
            mKeyStore.load(null);
            key = (PrivateKey) mKeyStore.getKey(KEY_NAME, null);
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException: " + e.toString();
            ;
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException: " + e.toString();
            ;
        } catch (UnrecoverableKeyException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException: " + e.toString();
            ;
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException: " + e.toString();
            ;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString();
            ;
        }
        if (key == null) {
            Log.e(TAG, errorMessage);
        }
        return key;
    }

    /**
     * Creates a symmetric key in the Android Key Store
     */
    public static boolean createKey() {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        try {
            mKeyStore.load(null);
            mKeyGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setUserAuthenticationRequired(false)
                    .build());
            mKeyGenerator.generateKeyPair();

            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = createKeyExceptionErrorPrefix + "NoSuchAlgorithmException: " + e.toString();
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException: " + e.toString();
            e.printStackTrace();
        } catch (CertificateException e) {
            errorMessage = createKeyExceptionErrorPrefix + "CertificateException: " + e.toString();
            e.printStackTrace();
        } catch (IOException e) {
            errorMessage = createKeyExceptionErrorPrefix + "IOException: " + e.toString();
            e.printStackTrace();
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
            setPluginResultError(errorMessage);
        }
        return isKeyCreated;
    }

    private byte[] signTransaction(String payload, String date) throws BadPaddingException, IllegalBlockSizeException {

        Signature signature = mCipher;
        // Include a client nonce in the transaction so that the nonce is also
        // signed
        // by the private key and the backend can verify that the same nonce
        // can't be used
        // to prevent replay attacks.
        Transaction transaction = new Transaction(payload, date);
        try {
            signature.update(transaction.toByteArray());
            byte[] sigBytes = signature.sign();
            return sigBytes;
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean setPluginResultError(String errorMessage) {
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        return false;
    }
}
