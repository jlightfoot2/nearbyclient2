package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class PKIActivity extends Activity {
    private static final String TAG = "PKIActivity";
    public String keyStoreAlias;
    public static final String CA_CN ="android-dha-ca.local";
    public static final String CA_CN_PATTERN ="CN=%s, O=DHA, OU=SDD";
    private CAHelper mCAHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pki);
        Log.v(TAG, "onCreate");
        keyStoreAlias = getString(R.string.android_key_store_alias);

        CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
        if(!caPreferences.isSetup()){
            Log.v(TAG,"Setting up ca");
            notifyUser("Setting up CA");
            try {
                Provider bcProvider = new BouncyCastleProvider();
                Security.addProvider(bcProvider);
                mCAHelper = new CAHelper(bcProvider,CA_CN_PATTERN,CA_CN);
                mCAHelper.init();

                
                KeyPair rootKeyPair = mCAHelper.getKeyPair();
                Log.v(TAG,"Private key info");
                Log.v(TAG,rootKeyPair.getPrivate().getAlgorithm());
                Log.v(TAG,rootKeyPair.getPrivate().getFormat());
                Log.v(TAG,"Public key info");
                Log.v(TAG,rootKeyPair.getPublic().getAlgorithm());
                Log.v(TAG,rootKeyPair.getPublic().getFormat());


                caPreferences.store(mCAHelper.getKeyPair(),mCAHelper.getCertificate());
//TODO move to test
//                  boolean keyPairRetrieved = false;
//                try {
//                    KeyPair storedKP = caPreferences.getKeyPair();
//                    keyPairRetrieved = true;
//                    byte[] storedPrivate = storedKP.getPrivate().getEncoded();
//                    if(Arrays.equals(storedPrivate,ogPrivatekey)){
//                        Log.v(TAG,"SUCCESS stored private key matches og");
//                        Log.v(TAG,new String(ogPrivatekey));
//                        Log.v(TAG,new String(storedPrivate));
//                    } else {
//                        Log.v(TAG,"FAILURE stored private key DOES NOT MATCH og");
//                    }
//                } catch (InvalidKeySpecException e) {
//                    e.printStackTrace();
//                } catch (CAPreferencePrivateKeyDecryptException e) {
//                    e.printStackTrace();
//                }
//
//                if(!keyPairRetrieved){
//                   Log.v(TAG,"FAILURE: could not retrieve stored key pair");
//                }
                notifyUser("CA Done");
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
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (CAPreferenceException e) {
                e.printStackTrace();
            }
        }else{
            Log.v(TAG,"CA already setup");
            notifyUser("CA already setup");
        }
    }

    private void notifyUser(String msg){

        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }

//    private PKCS10CertificationRequest createTestCSR(KeyPair keyPair) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException {
//        return CSRHelper.generateCSR(keyPair,CA_CN);
//    }

//    private KeyPair createRootKeyPairBC() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
//
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
//        keyPairGenerator.initialize(1024, new SecureRandom());
//
//        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        return keyPair;
//    }

//    public static X509Certificate signBC(PKCS10CertificationRequest inputCSR, KeyPair pair)
//            throws NoSuchProviderException, IOException,
//            OperatorCreationException, CertificateException, CertificateException {
//
//        String cnString = String.format(CA_CN_PATTERN, CA_CN);
//        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
//                .find("SHA1withRSA");
//        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
//                .find(sigAlgId);
//
//
//        AsymmetricKeyParameter caPrivateKey = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
//
//        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
//
//
//        Calendar cal = Calendar.getInstance();
//        Date today = cal.getTime();
//        cal.add(Calendar.YEAR, 3); // expires in 3 years
//        Date expiryYear = cal.getTime();
//
//        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
//                new X500Name(cnString),
//                new BigInteger("1"),
//                new Date(),
//                expiryYear,
//                inputCSR.getSubject(), //pk10Holder.getSubject(),
//                keyInfo);
//
//        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
//                .build(caPrivateKey);
//
//        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
//
//        Certificate eeX509CertificateStructure = holder.toASN1Structure();
//
//        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
//
//        // Read Certificate
//        InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
//        X509Certificate theCert =  (X509Certificate) cf.generateCertificate(is1);
//        is1.close();
//        return theCert;
//    }
}
