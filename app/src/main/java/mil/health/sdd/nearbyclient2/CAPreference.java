package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    private static final String CIPHER_SECRET_KEY_ALG = "AES";
    private static final String CIPHER_TRANSFORMATION = CIPHER_SECRET_KEY_ALG + "/GCM/NoPadding";

    private static final int CIPHER_KEY_SIZE_BYTES = 16;
    private static final int CIPHER_INIT_VECTOR_BYTES = 12;
    private static final int CIPHER_INIT_VECTOR_OFFSET_BYTES = 16 - CIPHER_INIT_VECTOR_BYTES;
    private static final int BASE64_CONF = Base64.NO_WRAP;
//    private KeyPair deviceKeyPair;
    public CAPreference(Context context,String share_prefs_filename){
        this.context = context;
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
//    /**
//     * This keypair not meant for signing. It is meant to encrypt the signing key to protect it.
//     *
//     */
//    public void loadDeviceKeypair(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
//                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
//        kpg.initialize(new KeyGenParameterSpec.Builder(
//                alias,
//                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
//                .setDigests(KeyProperties.DIGEST_SHA256,
//                        KeyProperties.DIGEST_SHA512)
//                .build());
//
//        KeyPair deviceKeyPair = kpg.generateKeyPair();
//    }

    public void encryptDecryptTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //see https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO zero out key
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG);

        //create init vector
        byte[] iv = new byte[CIPHER_INIT_VECTOR_BYTES]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv); //TODO zero out iv?

        //encrypt
        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        String plainText = "They're taking our jobs. Der Dekmi Derbs";
        byte[] plainTextBytesStart = plainText.getBytes();
        byte[] cipherText = cipher.doFinal(plainTextBytesStart); //Base64? //we're encrypted!

        //Decrypt process
        // deconstruct message

        ByteBuffer byteBuffer = ByteBuffer.allocate(CIPHER_INIT_VECTOR_OFFSET_BYTES + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        //init cipher and decrypt
        final Cipher cipher2 = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG), new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv));
//        if (associatedData != null) {
//            cipher2.updateAAD(associatedData);
//        }

        byte[] plainTextBytesEnd = cipher2.doFinal(cipherText);
        if(plainTextBytesEnd.equals(plainTextBytesEnd)){
            Log.v(TAG,"SUCCESS: Test Enctypted and decrypted");
            Log.v(TAG, new String(plainTextBytesEnd));
        } else {
            Log.e(TAG,"FAILED Enctypted and decrypted test message");
        }
    }

    private void initSecretKey(){

    }

    public byte[] encryptPrivateKey(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO zero out key
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, CIPHER_SECRET_KEY_ALG);

        //create init vector
        byte[] iv = new byte[CIPHER_INIT_VECTOR_BYTES]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv); //TODO zero out iv?

        //encrypt
        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] privateKeyEncoded = privateKey.getEncoded();
        return cipher.doFinal(privateKeyEncoded); //Base64? //we're encrypted!
    }
    //TODO this won't work until the privateKey issue is solved
    public byte[] decryptPrivateKey(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO find out how to handle storing and extracting private key
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

    public void store(KeyPair caKeyPair, X509Certificate caCert) throws CertificateEncodingException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
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

    public KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA",BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(caPrivateKeyBytes)); //need to decrypt here
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
