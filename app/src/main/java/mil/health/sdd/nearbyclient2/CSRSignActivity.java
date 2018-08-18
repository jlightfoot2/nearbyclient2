package mil.health.sdd.nearbyclient2;

import android.content.Intent;
import android.os.Bundle;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class CSRSignActivity extends AppCompatActivity implements CAPreference.CaPreferenceLoadListener {

    public String mKeyStoreAlias;
    public static final String TAG = "CSRSignActivity";
    CAPreference mCaPreferences;
    boolean mPrefsReady = false;
    CAPreference.PreferenceLoadHandler mPreferenceHandler;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_csrsign);
        Log.v(TAG,"onCreate");
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.v(TAG,"onResume");
        mPrefsReady = false;
        mKeyStoreAlias = getString(R.string.android_key_store_alias);
        mCaPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),mKeyStoreAlias,false);
        mPreferenceHandler = new CAPreference.PreferenceLoadHandler(this);
        Thread caThread = new Thread(new CaThread());
        caThread.start();
    }


    public void onCaPreferenceLoaded(CAPreference caPreference){
        Log.v(TAG,"onCaPreferenceLoaded called");
        Log.v(TAG,"caPreference isSetup: " + caPreference.isSetup());
        mPrefsReady = caPreference.isSetup();
        Intent intent = getIntent();
        String csrBase64 = intent.getStringExtra(NSDActivity.EXTRA_MESSAGE);
        Log.v(TAG,"Intent Extra: " + csrBase64);
        try {
            PKCS10CertificationRequest csr = loadCSR(csrBase64);
            X509Certificate signedClientCert = signCSR(csr);
            Log.v(TAG,"Certificate Signed Yay");
        } catch (Exception e) {
            Log.e(TAG,"load or sign Exception",e);
        }

        Intent mainIntent = new Intent(this, MainActivity.class);
        startActivity(mainIntent);
    }

    private X509Certificate signCSR(PKCS10CertificationRequest csrReq) throws InvalidKeySpecException, CAPreferencePrivateKeyDecryptException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, IOException {

        String issuerCNString = String.format(PKIActivity.CA_CN_PATTERN, PKIActivity.CA_CN);
        return CSRHelper.sign(csrReq,mCaPreferences.getKeyPair(),issuerCNString);
    }

    private PKCS10CertificationRequest loadCSR(String base64CSR) throws IOException {
        return new PKCS10CertificationRequest(Base64.decode(base64CSR,Base64.DEFAULT));
    }

    class CaThread implements Runnable {

        public void run() {
            mCaPreferences.init();
            Log.v(TAG,"CaThread implements Runnable");
            Message msg = mPreferenceHandler.obtainMessage(CAPreference.PreferenceLoadHandler.CA_INIT_COMPLETE,mCaPreferences);
            mPreferenceHandler.sendMessage(msg);
        }
    }
}
