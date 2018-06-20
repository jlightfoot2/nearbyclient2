package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;


public class PKIActivity extends Activity {
    private static final String TAG = "PKIActivity";

    private static final String CA_KEY_ALIAS = "andoidIotCA";
    private static final String CA_CN ="android-dha-ca.local";
    private static final String CA_CN_PATTERN ="CN=%s, O=DHA, OU=SDD";
    // private static final String CERT_DIR = "certs";
    // private static final String PRIVATE_KEY_FILE_NAME = "mqtt_client.key";
    // private static final String CA_FILE_NAME = "ca.key";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pki);
        Log.v(TAG, "onCreate");


        CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename));
        if(!caPreferences.isSetup()){
            Log.v(TAG,"Setting up ca");
            try {
                Provider bcProvider = new BouncyCastleProvider();
                Security.addProvider(bcProvider);
                KeyPair rootKeyPair = createRootKeyPairBC();
                Log.v(TAG,"Private key info");
                Log.v(TAG,rootKeyPair.getPrivate().getAlgorithm());
                Log.v(TAG,rootKeyPair.getPrivate().getFormat());
                Log.v(TAG,"Public key info");
                Log.v(TAG,rootKeyPair.getPublic().getAlgorithm());
                Log.v(TAG,rootKeyPair.getPublic().getFormat());

                PKCS10CertificationRequest testCSR = createTestCSR(rootKeyPair);
                X509Certificate caCert = signBC(testCSR,rootKeyPair); //we are self-signing

                caPreferences.store(rootKeyPair,caCert);

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
            } catch (OperatorCreationException e) {
                e.printStackTrace();
            }
        }else{
            Log.v(TAG,"CA already setup");
        }
    }


    private PKCS10CertificationRequest createTestCSR(KeyPair keyPair) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
        return CSRHelper.generateCSR(keyPair,CA_CN);
    }

    private KeyPair createRootKeyPairBC() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public static X509Certificate signBC(PKCS10CertificationRequest inputCSR, KeyPair pair)
            throws NoSuchProviderException, IOException,
            OperatorCreationException, CertificateException, CertificateException {

        String cnString = String.format(CA_CN_PATTERN, CA_CN);
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                .find(sigAlgId);


        AsymmetricKeyParameter caPrivateKey = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());

        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());


        Calendar cal = Calendar.getInstance();
        Date today = cal.getTime();
        cal.add(Calendar.YEAR, 3); // expires in 3 years
        Date expiryYear = cal.getTime();

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                new X500Name(cnString),
                new BigInteger("1"),
                new Date(),
                expiryYear,
                inputCSR.getSubject(), //pk10Holder.getSubject(),
                keyInfo);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                .build(caPrivateKey);

        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);

        Certificate eeX509CertificateStructure = holder.toASN1Structure();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);

        // Read Certificate
        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
        X509Certificate theCert =  (X509Certificate) cf.generateCertificate(is1);
        is1.close();
        return theCert;
    }
}
