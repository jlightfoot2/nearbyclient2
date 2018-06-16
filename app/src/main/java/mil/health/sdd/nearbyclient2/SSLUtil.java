package mil.health.sdd.nearbyclient2;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

class SSlUtil {
    private static final String TAG = "SslUtil";
    private static final String COMMON_NAME = "android-things-ca-testy-test.local";
    private static final int KEY_SIZE = 2048;
    static SSLSocketFactory getSocketFactory (InputStream caStream, InputStream certStream, InputStream keyStream,
                                              String password) throws Exception
    {
        Log.v(TAG,"SslUtil.getSocketFactory called");
        Security.addProvider(new BouncyCastleProvider());

        // load CA certificate
        X509Certificate caCert = null;


        BufferedInputStream bis = new BufferedInputStream(caStream);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Log.v(TAG,"BufferedInputStream::CA");
        while (bis.available() > 0) {
            caCert = (X509Certificate) cf.generateCertificate(bis);
            System.out.println(caCert.toString());
            Log.v(TAG,caCert.toString());
        }

        // load client certificate
        bis = new BufferedInputStream(certStream);
        X509Certificate cert = null;
        Log.v(TAG,"BufferedInputStream::Cert");
        while (bis.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bis);
            // System.out.println(caCert.toString());
            Log.v(TAG,cert.toString());
        }

        // load client private key
        PEMParser pemParser = new PEMParser(new InputStreamReader(keyStream));
        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
                .build(password.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                .setProvider("BC");
        KeyPair key;
        if (object instanceof PEMEncryptedKeyPair) {
            Log.v(TAG,"Encrypted key - we will use provided password");
            key = converter.getKeyPair(((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(decProv));
        } else {
            Log.v(TAG,"Unencrypted key - no password needed");
            key = converter.getKeyPair((PEMKeyPair) object);
        }
        pemParser.close();

        // CA certificate is used to authenticate server
        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        caKs.setCertificateEntry("ca-certificate", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(caKs);



        // client key and certificates are sent to server so it can authenticate
        // us
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("certificate", cert);
        ks.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[] { cert });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());

        // finally, create SSL socket factory
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return context.getSocketFactory();
    }

    public KeyPair createPrivateKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        kpg.initialize(new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build());

        KeyPair keyPair = kpg.generateKeyPair();
        return keyPair;
    }

    public PKCS10CertificationRequest createCSR333(KeyPair pair) throws OperatorCreationException {
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Requested Test Certificate"), pair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(pair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        return csr;
    }

    public PKCS10CertificationRequest createCSR() throws NoSuchAlgorithmException, IOException, OperatorCreationException {
//Generate KeyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

//Generate CSR in PKCS#10 format encoded in DER
        PKCS10CertificationRequest csr = CSRHelper.generateCSR(keyPair, COMMON_NAME);
//        byte  CSRder[] = csr.getEncoded();
        //TODO SIGN with furnished CA
        return csr;
    }
}
