package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class CAPreferencePrivateKeyDecryptException extends Exception{
    public CAPreferencePrivateKeyDecryptException(String message,Exception e){
        super(message,e);
    }
}

class CAPreferenceException extends Exception{
    public CAPreferenceException(String message,Exception e){
        super(message,e);
    }
}

public class CAPreference {
    private Context context;
    private static final String TAG = "CAPreference";
    private SharedPreferences sharedPreferences;
    private String caPrivateKeyPref;
    private String caPublicKeyPref;
    private String caCertificatePref;
    public byte[] caPrivateKeyBytes;
    public byte[] caPublicKeyBytes;
    public byte[] caCertificateBytes;

    private static final int CIPHER_BLOCK_SIZE_BITS = 128;
    private static final String CIPHER_SECRET_KEY_ALG = KeyProperties.KEY_ALGORITHM_AES;
    private static final String CIPHER_TRANSFORMATION = CIPHER_SECRET_KEY_ALG + "/GCM/NoPadding";
    private String androidKeyStoreAlias;
    private static final int CIPHER_KEY_SIZE_BYTES = 16;
    private static final int CIPHER_INIT_VECTOR_BYTES = 12;
    private static final int CIPHER_INIT_VECTOR_OFFSET_BYTES = 16 - CIPHER_INIT_VECTOR_BYTES;
    private static final int BASE64_CONF = Base64.NO_WRAP;
//    private KeyPair deviceKeyPair;
    public CAPreference(Context context,String share_prefs_filename,String androidKeyStoreAlias){
        this.context = context;
        this.androidKeyStoreAlias = androidKeyStoreAlias;
        sharedPreferences = this.context.getSharedPreferences(share_prefs_filename, Context.MODE_PRIVATE);

        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        this.retrieveRawCerts();
    }

    private void retrieveRawCerts(){
        caPrivateKeyPref = sharedPreferences.getString(context.getString(R.string.ca_private_key_name),""); //this will be encrypted
        caPublicKeyPref = sharedPreferences.getString(context.getString(R.string.ca_public_key_name),"");
        caCertificatePref = sharedPreferences.getString(context.getString(R.string.ca_x509_cert_name),"");
        if(isSetup()){
            this.decodeCerts();
        }
    }

    public boolean isSetup(){
        return !(caPrivateKeyPref.isEmpty() || caPublicKeyPref.isEmpty() || caCertificatePref.isEmpty());
    }

//    public void encryptDecryptTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        //see https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
//        SecureRandom secureRandom = new SecureRandom();
//        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO zero out key
//        secureRandom.nextBytes(key);
//        SecretKey secretKey = new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG);
//
//        //create init vector
//        byte[] iv = new byte[CIPHER_INIT_VECTOR_BYTES]; //NEVER REUSE THIS IV WITH SAME KEY
//        secureRandom.nextBytes(iv); //TODO zero out iv?
//
//        //encrypt
//        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
//        GCMParameterSpec parameterSpec = new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv); //128 bit auth tag length
//        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
//        String plainText = "They're taking our jobs. Der Dekmi Derbs";
//        byte[] plainTextBytesStart = plainText.getBytes();
//        byte[] cipherText = cipher.doFinal(plainTextBytesStart); //Base64? //we're encrypted!
//
//        //Decrypt process
//        // deconstruct message
//
//        ByteBuffer byteBuffer = ByteBuffer.allocate(CIPHER_INIT_VECTOR_OFFSET_BYTES + iv.length + cipherText.length);
//        byteBuffer.putInt(iv.length);
//        byteBuffer.put(iv);
//        byteBuffer.put(cipherText);
//        byte[] cipherMessage = byteBuffer.array();
//
//        //init cipher and decrypt
//        final Cipher cipher2 = Cipher.getInstance(CIPHER_TRANSFORMATION);
//        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG), new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv));
//
//        byte[] plainTextBytesEnd = cipher2.doFinal(cipherText);
//        if(plainTextBytesEnd.equals(plainTextBytesEnd)){
//            Log.v(TAG,"SUCCESS: Test Enctypted and decrypted");
//            Log.v(TAG, new String(plainTextBytesEnd));
//        } else {
//            Log.e(TAG,"FAILED Enctypted and decrypted test message");
//        }
//    }

    public void testEncDec(){
        String message = "The quick brown fox jumped over the lazy dog";
        byte[] messageBytes = message.getBytes();
        try {
            byte[] messageBytesEnc = encryptBytes(messageBytes);
            Log.v(TAG,"Encrypted Data: " + new String(messageBytesEnc));
            byte[] messageByteDec = decryptBytes(messageBytesEnc);
            if(messageByteDec.equals(messageBytes)){
                Log.v(TAG,"SUCCESS:  encryptBytes and decryptBytes worked");
                Log.v(TAG,"original: " + new String(messageBytes));
                Log.v(TAG,"decrypted: " + new String(messageByteDec));
            }
        } catch (Exception e) {
            Log.e(TAG,"testEncDec exception",e);
        }
    }

    private void initSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(CIPHER_SECRET_KEY_ALG, "AndroidKeyStore");

        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(androidKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build();

        keyGenerator.init(keyGenParameterSpec);
        final SecretKey secretKey = keyGenerator.generateKey();

        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    private SecretKey getSecretKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        boolean hasErrors = false;
        if(!keyStore.containsAlias(androidKeyStoreAlias)){
            try {
                initSecretKey();
            } catch (NoSuchProviderException e) {
                hasErrors = true;
                //TODO rethrow generic exceptions and add og exception to the trace?
                //remove "return null"
                Log.e(TAG, "initSecretKey",e);
            } catch (InvalidAlgorithmParameterException e) {
                hasErrors = true;
                Log.e(TAG, "initSecretKey",e);

            } catch (NoSuchPaddingException e) {
                hasErrors = true;
                Log.e(TAG, "initSecretKey",e);

            } catch (InvalidKeyException e) {
                hasErrors = true;
                Log.e(TAG, "initSecretKey",e);

            }
        }
        if(hasErrors){
          return null;
        }

        keyStore.load(null);
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(androidKeyStoreAlias, null);

        return secretKeyEntry.getSecretKey();
    }

    private byte[] encryptBytes(byte[] plainMessage) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom secureRandom = new SecureRandom();
        SecretKey secretKey = getSecretKey();

        //create init vector
        byte[] iv = new byte[CIPHER_INIT_VECTOR_BYTES]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv); //TODO zero out iv?

        //encrypt
        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv); //128 bit auth tag length
        //TODO java.security.InvalidAlgorithmParameterException: Caller-provided IV not permitted
        /*
https://github.com/googlesamples/android-FingerprintDialog/issues/10
https://stackoverflow.com/questions/33214469/issue-while-using-android-fingerprint-iv-required-when-decrypting-use-ivparame
https://proandroiddev.com/secure-data-in-android-initialization-vector-6ca1c659762c  //TODO start here

        */
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        return cipher.doFinal(plainMessage); //Base64? //we're encrypted!
    }

    public byte[] decryptBytes(byte[] cipherText) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO find out how to handle storing and extracting private key
        SecretKey secretKey = getSecretKey();
        byte[] iv = new byte[CIPHER_INIT_VECTOR_BYTES];
        ByteBuffer byteBuffer = ByteBuffer.allocate(CIPHER_INIT_VECTOR_OFFSET_BYTES + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        //init cipher and decrypt
        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG), new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv));

        return cipher.doFinal(cipherText);
    }

    public byte[] encryptPrivateKey(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException {

        return encryptBytes(privateKey.getEncoded());
    }
    //TODO this won't work until the privateKey issue is solved
    public byte[] decryptPrivateKey(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException {

        byte[] decryptedKey = decryptBytes(cipherText);
        return decryptedKey;//TODO change method to return private key
    }

    public void store(KeyPair caKeyPair, X509Certificate caCert) throws CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, IOException {
        SharedPreferences.Editor pkiEditor = sharedPreferences.edit();
        pkiEditor.putString(context.getString(R.string.ca_public_key_name), Base64.encodeToString(caKeyPair.getPublic().getEncoded(), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_private_key_name), Base64.encodeToString(encryptPrivateKey(caKeyPair.getPrivate()), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_x509_cert_name), Base64.encodeToString(caCert.getEncoded(), BASE64_CONF));
        pkiEditor.commit();
        this.retrieveRawCerts();
    }

    public void deleteAll() {
        SharedPreferences.Editor pkiEditor = sharedPreferences.edit();
        pkiEditor.putString(context.getString(R.string.ca_public_key_name), "");
        pkiEditor.putString(context.getString(R.string.ca_private_key_name), "");
        pkiEditor.putString(context.getString(R.string.ca_x509_cert_name), "");
        pkiEditor.commit();
        this.retrieveRawCerts();
    }

    private void decodeCerts(){
        caPrivateKeyBytes  = Base64.decode(caPrivateKeyPref, BASE64_CONF); //This is encrypted
        caPublicKeyBytes  = Base64.decode(caPublicKeyPref, BASE64_CONF);
        caCertificateBytes  = Base64.decode(caCertificatePref, BASE64_CONF);
    }

    public KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, CAPreferencePrivateKeyDecryptException {
        KeyFactory kf = KeyFactory.getInstance("RSA",BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey privateKey = null; //need to decrypt here
        try {
            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decryptPrivateKey(caPrivateKeyBytes)));
        } catch (Exception e) {
            Log.e(TAG,"Could not decrypt private key",e);
            throw new CAPreferencePrivateKeyDecryptException("Could not decrypt private key",e);
        }
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(caPublicKeyBytes));
        return new KeyPair(publicKey,privateKey);
    }

    public  X509Certificate getCertificate() throws CertificateException {
//        KeyFactory kf = KeyFactory.getInstance("RSA",BouncyCastleProvider.PROVIDER_NAME);
//        X509Certificate x509Cert = (X509Certificate) kf.generatePublic(new X509EncodedKeySpec(caCertificateBytes));
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(caCertificateBytes);
        return (X509Certificate) certFactory.generateCertificate(in);
    }

}
