package mil.health.sdd.nearbyclient2;

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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class CAHelper {

    private String caCNString;
    private String caCN;
    private Provider provider;
    private KeyPair mCAKeyPair;
    private X509Certificate mCACertificate; //x509
    public CAHelper(Provider provider,String caCNString, String caCN){
        this.caCNString = caCNString;
        this.caCN = caCN;
        this.provider = provider;
    }

    /**
     * Creates new keypair to initialize CAHelper
     *
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws OperatorCreationException
     * @throws IOException
     * @throws CertificateException
     */
    public void init() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException, CertificateException {
        mCAKeyPair = makeKeyPair();
        mCACertificate = selfSign(generateCSR(mCAKeyPair),mCAKeyPair);
    }

    /**
     * Use existing key pair and cert to initialize CAHelper
     *
     * @param caKeyPair
     * @param caCertificate
     */
    public void init(KeyPair caKeyPair, X509Certificate caCertificate) {
        mCAKeyPair = caKeyPair;
        mCACertificate = caCertificate;
        //TODO verify ca?
    }

    private X509Certificate selfSign(PKCS10CertificationRequest inputCSR, KeyPair pair) throws NoSuchProviderException, IOException,
            OperatorCreationException, CertificateException, CertificateException {


            String cnString = String.format(this.caCNString, this.caCN);
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

    public PKCS10CertificationRequest generateCSR(KeyPair keyPair) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
        return CSRHelper.generateCSR(keyPair,caCN);
    }

    private KeyPair makeKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider.getName());
        keyPairGenerator.initialize(1024, new SecureRandom());

        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public KeyPair getKeyPair(){
        return mCAKeyPair;
    }

    public X509Certificate getCertificate() {
        return mCACertificate;
    }
}
