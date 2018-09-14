package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Message;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

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


    private static final int SERVER_CLIENT_ACCEPTED = 2;

    private static final int CIPHER_BLOCK_SIZE_BITS = 128;
    private static final String CIPHER_SECRET_KEY_ALG = KeyProperties.KEY_ALGORITHM_AES;
    private static final String CIPHER_TRANSFORMATION = CIPHER_SECRET_KEY_ALG + "/GCM/NoPadding";
    private String androidKeyStoreAlias;
    private static final int CIPHER_KEY_SIZE_BYTES = 16;
    private static final int CIPHER_INIT_VECTOR_BYTES = 12;
    private static final int CIPHER_INIT_VECTOR_OFFSET_BYTES = 16 - CIPHER_INIT_VECTOR_BYTES;
    private static final int BASE64_CONF = Base64.NO_WRAP;
//    private KeyPair deviceKeyPair;

    /**
     * @deprecated this.retrieveRawCerts() is process intensive and should only be run via init() method
     * TODO: 8/17/18  this.retrieveRawCerts() from constructor.
     *
     * @param context
     * @param share_prefs_filename
     * @param androidKeyStoreAlias
     * @param autoInit
     */
    public CAPreference(Context context,String share_prefs_filename,String androidKeyStoreAlias, boolean autoInit){
        this.context = context;
        this.androidKeyStoreAlias = androidKeyStoreAlias;
        sharedPreferences = this.context.getSharedPreferences(share_prefs_filename, Context.MODE_PRIVATE);

        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        if(autoInit){
            this.retrieveRawCerts();
        }
    }

    public CAPreference(Context context,String share_prefs_filename,String androidKeyStoreAlias){
        this(context,share_prefs_filename,androidKeyStoreAlias,true);
    }

    public void init(){
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

    public void setTempSecret(byte[] secretKey){

        sharedPreferences.edit().putString(context.getString(R.string.ca_secret_key_name), Base64.encodeToString(secretKey, BASE64_CONF));

    }

    /**
     *
     * @param secretKey
     * @return base64 encoded string
     */
    public String getTempSecret(byte[] secretKey){
        return sharedPreferences.getString(context.getString(R.string.ca_secret_key_name),"");
    }

    //TODO remove and put in a unit or component test.
    public void testEncDec(){
        String message = "The quick brown fox jumped over the lazy dog";
        byte[] messageBytes = message.getBytes();
        try {
            byte[] messageBytesEnc = encryptBytes(messageBytes);
            Log.v(TAG,"Encrypted Data: " + new String(messageBytesEnc));
            byte[] messageByteDec = decryptBytes(messageBytesEnc);
            if(Arrays.equals(messageBytes,messageByteDec)){
                Log.v(TAG,"SUCCESS:  encryptBytes and decryptBytes worked");
                Log.v(TAG,"original: " + new String(messageBytes));
                Log.v(TAG,"decrypted: " + new String(messageByteDec));
            } else {
                Log.v(TAG,"FAILED:  encryptBytes and decryptBytes worked");
                Log.v(TAG,"original: " + new String(messageBytes));
                Log.v(TAG,"decrypted: " + new String(messageByteDec));
            }
        } catch (Exception e) {
            Log.e(TAG,"testEncDec exception",e);
        }
    }

    public void testCAPrivateKeyStoreRetrieve(){

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
        }else{
            Log.v(TAG,"Yes keystore DOES contain " + androidKeyStoreAlias);
        }
        if(hasErrors){
          return null;
        }

//        keyStore.load(null);
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(androidKeyStoreAlias, null);

        return secretKeyEntry.getSecretKey();
    }

    private byte[] encryptBytes(byte[] plainMessage) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CAPreferenceException {

        SecretKey secretKey = getSecretKey();

        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

        //test1 trying without parametric spec cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();


        if(iv.length != 12){
          throw new CAPreferenceException("Invalid Iv Length");
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(iv);
        outputStream.write(cipher.doFinal(plainMessage));
        return outputStream.toByteArray();
    }

    public byte[] decryptBytes(byte[] cipherText) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = new byte[CIPHER_KEY_SIZE_BYTES]; //TODO find out how to handle storing and extracting private key
        byte[] iv = Arrays.copyOfRange(cipherText,0,CIPHER_INIT_VECTOR_BYTES);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(CIPHER_BLOCK_SIZE_BITS, iv);
        SecretKey secretKey = getSecretKey();

        final Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(Arrays.copyOfRange(cipherText,CIPHER_INIT_VECTOR_BYTES,cipherText.length));
    }

    public byte[] encryptPrivateKey(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException, CAPreferenceException {

        return encryptBytes(privateKey.getEncoded());
    }

    public byte[] decryptPrivateKey(byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException {

        byte[] decryptedKey = decryptBytes(cipherText);
        return decryptedKey;//TODO change method to return private key
    }

    public void store(KeyPair caKeyPair, X509Certificate caCert) throws CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, IOException, CAPreferenceException {
        SharedPreferences.Editor pkiEditor = sharedPreferences.edit();
        pkiEditor.putString(context.getString(R.string.ca_public_key_name), Base64.encodeToString(caKeyPair.getPublic().getEncoded(), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_private_key_name), Base64.encodeToString(encryptPrivateKey(caKeyPair.getPrivate()), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_x509_cert_name), Base64.encodeToString(caCert.getEncoded(), BASE64_CONF));
        pkiEditor.commit();
        this.retrieveRawCerts();
    }

    public static CertInfo getCertInfo(X509Certificate cert) throws CertificateEncodingException {
      CertInfo certInfo = new CertInfo();
        X500Name x500Name = new JcaX509CertificateHolder(cert).getSubject();
        Principal p = cert.getSubjectDN();
        Log.v(TAG,p.getName());

//        RDN email = x500Name.getRDNs(BCStyle.EmailAddress)[0];
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        RDN organization = x500Name.getRDNs(BCStyle.O)[0];
        RDN organizationUnit = x500Name.getRDNs(BCStyle.OU)[0];
        RDN country = x500Name.getRDNs(BCStyle.C)[0];
        RDN locality = x500Name.getRDNs(BCStyle.L)[0];
        RDN state = x500Name.getRDNs(BCStyle.ST)[0];
        String cnStr = cn.getFirst().getValue().toString();
        String organizationStr = organization.getFirst().getValue().toString();
        String organizationUnitStr = organizationUnit.getFirst().getValue().toString();
        String countryStr = country.getFirst().getValue().toString();
        String localityStr = locality.getFirst().getValue().toString();
        String stateStr = state.getFirst().getValue().toString();
        certInfo.setCountry(countryStr);
        certInfo.setCn(cnStr);
        certInfo.setOrganization(organizationStr);
        certInfo.setLocality(localityStr);
        certInfo.setState(stateStr);
        return certInfo;
    }

    public void deleteAll() {
        SharedPreferences.Editor pkiEditor = sharedPreferences.edit();
        pkiEditor.putString(context.getString(R.string.ca_public_key_name), "");
        pkiEditor.putString(context.getString(R.string.ca_private_key_name), "");
        pkiEditor.putString(context.getString(R.string.ca_x509_cert_name), "");
        pkiEditor.commit();
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(androidKeyStoreAlias);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

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


    public static class PreferenceLoadHandler extends Handler{
        public static final int CA_INIT_COMPLETE = 1;
        private final WeakReference<CaPreferenceLoadListener> mCaListener;
        public PreferenceLoadHandler(CaPreferenceLoadListener CAPreference){
            mCaListener = new WeakReference<CaPreferenceLoadListener>(CAPreference);
        }

        @Override
        public void handleMessage(Message msg) {
            CaPreferenceLoadListener pref = (CaPreferenceLoadListener) mCaListener.get();
            CAPreference caPref = (CAPreference) msg.obj;
            Log.v(TAG,"JWEHandler.handleMessage");
            if(msg.what == CA_INIT_COMPLETE){
                pref.onCaPreferenceLoaded(caPref);
            }
        }
    }

    public static interface CaPreferenceLoadListener{
        void onCaPreferenceLoaded(CAPreference pref);
    }

    public static class CAPreferencePrivateKeyDecryptException extends Exception{
        public CAPreferencePrivateKeyDecryptException(String message,Exception e){
            super(message,e);
        }
    }

    public static class CAPreferenceException extends Exception{

        public CAPreferenceException(String message){
            super(message);
        }

        public CAPreferenceException(String message,Exception e){
            super(message,e);
        }
    }
}
