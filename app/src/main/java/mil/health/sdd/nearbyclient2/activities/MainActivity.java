package mil.health.sdd.nearbyclient2.activities;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import mil.health.sdd.nearbyclient2.CAPreference;
import mil.health.sdd.nearbyclient2.R;

public class MainActivity extends AppCompatActivity {
    public static final String EXTRA_ADVERTISE_MESSAGE = "mil.health.sdd.nearbyclient2.ADVERTISE_MESSAGE";
    public static final String EXTRA_ADVERTISE_MESSAGE_STRING = "user_button";
    public static final String TAG = "MainActivity";
    public static final String EXTRA_MESSAGE = "mil.health.sdd.nearbyclient2.MESSAGE";
    public String keyStoreAlias;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        keyStoreAlias = getString(R.string.android_key_store_alias);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {

        } else {

        }
    }
    @Override
    public void onStart(){
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                    1);
        } else {
            notifyUser("PERMISSION GRANTED FOR WRITE_EXTERNAL_STORAGE" );
        }
       super.onStart();
    }

    /** Called when the user taps the Advertise button */
    public void advertiseCA(View view) {
        Intent intent = new Intent(this, AdvertiseCAActivity.class);
        intent.putExtra(EXTRA_ADVERTISE_MESSAGE, EXTRA_ADVERTISE_MESSAGE_STRING);
        startActivity(intent);
    }

    public void testSomething(View view){
        String testString = "zVaywe8OHn2g-ARVp2NC-g";
        byte[] decodedKey = Base64.decode(testString,Base64.URL_SAFE);
        Log.v(TAG,"DFSDF: Base64.URL_SAFE" );
        Log.v(TAG,"KEY: " + testString);
        Log.v(TAG,"KEY_LENGTH: " + decodedKey.length);
    }

    public void setupCertificates(View view) {
        Intent intent = new Intent(this, PKIActivity.class);
        startActivity(intent);
    }

    public void handleStoredCSRs(View view) {
        Intent intent = new Intent(this, CSRFilesActivity.class);
        startActivity(intent);
    }

//    public void registerCAService(View view){
//        Intent intent = new Intent(this, NSDActivity.class);
//        startActivity(intent);
//    }

    public void manageSignedCerts(View view) {
        Intent intent = new Intent(this, CertFilesActivity.class);
        startActivity(intent);
    }

    public void scanCode(View view) {
        Intent intent = new Intent(this, CodeScanActivity.class);
        startActivity(intent);
    }


    public void deleteCertificates(View view) {
        CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
        caPreferences.deleteAll();
        notifyUser("Keys and Certs deleted");
    }

    private void notifyUser(String msg){

        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }
}
