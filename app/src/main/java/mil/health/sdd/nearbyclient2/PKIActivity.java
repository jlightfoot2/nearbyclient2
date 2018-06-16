package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class PKIActivity extends Activity {
    private static final String TAG = "PKIActivity";
    private static final String AndroidKeyStore = "AndroidKeyStore";

    private static final String KEY_ALIAS = "andoidIotCA";
    // private static final String CERT_DIR = "certs";
    // private static final String PRIVATE_KEY_FILE_NAME = "mqtt_client.key";
    // private static final String CA_FILE_NAME = "ca.key";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pki);
        Log.v(TAG, "onCreate");
        try {
            KeyPair rootKeyPair = createRootKeyPair();
            PKCS10CertificationRequest testCSR = createTestCSR();
            sign(testCSR,rootKeyPair);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
    }


    private KeyPair createRootKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
//                .setCertificateSubject(new X500Principal("CN=Test Root CA Test Certificate"))
                .build());

        return kpg.generateKeyPair();
    }

//    private void getSignedCert(PKCS10CertificationRequest inputCSR, KeyPair caKeyPair) throws IOException {
//
//        //public static X509Certificate sign
//
//        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
//
//        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
//
//        AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caKeyPair.getPrivate().getEncoded()); //Todo Rename
//
//        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded());
//    }

    public static X509Certificate sign(PKCS10CertificationRequest inputCSR, KeyPair pair)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException,
            OperatorCreationException, CertificateException {

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);
    //TODO test if private key is empty
        //TODO try debugger
        AsymmetricKeyParameter caPrivateKey = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());

        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());


        //PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR.getEncoded());

        Calendar cal = Calendar.getInstance();
        Date today = cal.getTime();
        cal.add(Calendar.YEAR, 3); // expires in 3 years
        Date expiryYear = cal.getTime();

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                new X500Name("CN=issuer"),
                new BigInteger("1"),
                new Date(),
                expiryYear,
                inputCSR.getSubject(), //pk10Holder.getSubject(),
                keyInfo);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                .build(caPrivateKey);

        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);

        Certificate eeX509CertificateStructure = holder.toASN1Structure();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        X509Certificate theCert =  (X509Certificate) cf.generateCertificate(is1);
        is1.close();
        return theCert;
    }

    private PKCS10CertificationRequest createTestCSR() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
        SSlUtil sslUtil = new SSlUtil();
        return sslUtil.createCSR();
    }
}
