package mil.health.sdd.nearbyclient2.activities;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentTransaction;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
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

import mil.health.sdd.nearbyclient2.helper.CAHelper;
import mil.health.sdd.nearbyclient2.CAPreference;
import mil.health.sdd.nearbyclient2.fragments.CaCertEditFragment;
import mil.health.sdd.nearbyclient2.fragments.CaCertFragment;
import mil.health.sdd.nearbyclient2.CertInfo;
import mil.health.sdd.nearbyclient2.R;

//import android.app.FragmentManager;
//import android.app.FragmentTransaction;




public class PKIActivity extends AppCompatActivity implements CaCertFragment.CaCertificateListener, CaCertEditFragment.EditCaCertListener {
    private static final String TAG = "PKIActivity";
    public String keyStoreAlias;
    public static final String CA_CN ="android-dha-ca.local";
    public static final String CA_CN_PATTERN ="CN=%s, O=DHA, OU=SDD";
    private CAHelper mCAHelper;
    private CAPreference caPreferences;
    private boolean caSetup = false;
    CaCertFragment certFragment;
    CaCertEditFragment certEditFragment;
    Provider bcProvider;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pki);
        Log.v(TAG, "onCreate");
        keyStoreAlias = getString(R.string.android_key_store_alias);

        bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
        caSetup = caPreferences.isSetup();
        FragmentManager fm = getSupportFragmentManager();
        if(!caSetup){
            certEditFragment = new CaCertEditFragment();
            FragmentTransaction ft1 = fm.beginTransaction();
            ft1.add(R.id.fragmentCaCertContainer,certEditFragment);
            ft1.commit();
        }else{
            Log.v(TAG,"CA already setup");
            notifyUser("CA already setup");
            Log.v(TAG,"adding fragment");

            try {
                Log.v(TAG,caPreferences.getCertificate().toString());
                CertInfo certInfo = CAPreference.getCertInfo(caPreferences.getCertificate());
                Log.v(TAG,certInfo.toString());
                certFragment = new CaCertFragment();
                certFragment.setCert(certInfo);
            } catch (CertificateException e) {
                Log.e(TAG,"CertificateException",e);
            }

            FragmentTransaction ft2 = fm.beginTransaction();
            ft2.add(R.id.fragmentCaCertContainer,certFragment);
            ft2.commit();
        }
    }

    public void onClickDelete(){
        Log.v(TAG,"onClickDelete");
        AlertDialog.Builder builder = new AlertDialog.Builder(this);


        builder.setMessage("You sure about that?")
                .setTitle("Confirm");

        builder.setPositiveButton("Yep", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                // User clicked OK button
                caPreferences.deleteAll();
                caSetup = caPreferences.isSetup();
                FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
                if(!(certFragment == null)){
                    transaction.remove(certFragment);
                    transaction.commit();
                    certFragment = null;

                    certEditFragment = new CaCertEditFragment();
                    FragmentTransaction ft1 = getSupportFragmentManager().beginTransaction();
                    ft1.replace(R.id.fragmentCaCertContainer,certEditFragment);
                    ft1.commit();
                }

            }
        });

        builder.setNegativeButton("Nope", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                // User cancelled the dialog
            }
        });

        AlertDialog dialog = builder.create();
        dialog.show();
    }

    public void submitCaCert(CertInfo certInfo){
        buildCaKeys(certInfo);
        FragmentManager fm = getSupportFragmentManager();
        FragmentTransaction ft2 = fm.beginTransaction();
        certFragment = new CaCertFragment();
        certFragment.setCert(certInfo);
        ft2.replace(R.id.fragmentCaCertContainer,certFragment);
        ft2.commit();
    }

    private void buildCaKeys(CertInfo certInfo){
        try {

            mCAHelper = new CAHelper(bcProvider,certInfo);
            mCAHelper.init();


            KeyPair rootKeyPair = mCAHelper.getKeyPair();
            Log.v(TAG,"Private key info");
            Log.v(TAG,rootKeyPair.getPrivate().getAlgorithm());
            Log.v(TAG,rootKeyPair.getPrivate().getFormat());
            Log.v(TAG,"Public key info");
            Log.v(TAG,rootKeyPair.getPublic().getAlgorithm());
            Log.v(TAG,rootKeyPair.getPublic().getFormat());

            caPreferences.store(mCAHelper.getKeyPair(),mCAHelper.getCertificate());

            notifyUser("CA Done");
            caSetup = true;
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
        } catch (CAPreference.CAPreferenceException e) {
            e.printStackTrace();
        }
    }

    private void notifyUser(String msg){

        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }
}
