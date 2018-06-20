package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CAPreference {
    private Context context;
    private SharedPreferences sharedPreferences;
    private String caPrivateKeyPref;
    private String caPublicKeyPref;
    private String caCertificatePref;
    public byte[] caPrivateKeyBytes;
    public byte[] caPublicKeyBytes;
    public byte[] caCertificateBytes;
    private static final int BASE64_CONF = Base64.NO_WRAP;
    public CAPreference(Context context,String share_prefs_filename){
        this.context = context;
        sharedPreferences = this.context.getSharedPreferences(share_prefs_filename, Context.MODE_PRIVATE);

        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        this.retrieveRawCerts();
    }

    private void retrieveRawCerts(){
        caPrivateKeyPref = sharedPreferences.getString(context.getString(R.string.ca_private_key_name),"");
        caPublicKeyPref = sharedPreferences.getString(context.getString(R.string.ca_public_key_name),"");
        caCertificatePref = sharedPreferences.getString(context.getString(R.string.ca_x509_cert_name),"");
        if(isSetup()){
            this.decodeCerts();
        }
    }

    public boolean isSetup(){
        return !(caPrivateKeyPref.isEmpty() || caPublicKeyPref.isEmpty() || caCertificatePref.isEmpty());
    }

    public void store(KeyPair caKeyPair, X509Certificate caCert) throws CertificateEncodingException {
        SharedPreferences.Editor pkiEditor = sharedPreferences.edit();
        pkiEditor.putString(context.getString(R.string.ca_public_key_name), Base64.encodeToString(caKeyPair.getPublic().getEncoded(), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_private_key_name), Base64.encodeToString(caKeyPair.getPrivate().getEncoded(), BASE64_CONF));
        pkiEditor.putString(context.getString(R.string.ca_x509_cert_name), Base64.encodeToString(caCert.getEncoded(), BASE64_CONF));
        pkiEditor.commit();
        this.retrieveRawCerts();
    }

    private void decodeCerts(){
        caPrivateKeyBytes  = Base64.decode(caPrivateKeyPref, BASE64_CONF);
        caPublicKeyBytes  = Base64.decode(caPublicKeyPref, BASE64_CONF);
        caCertificateBytes  = Base64.decode(caCertificatePref, BASE64_CONF);
    }

    public KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA",BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(caPrivateKeyBytes));
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
