package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

public class MainActivity extends Activity {
    public static final String EXTRA_ADVERTISE_MESSAGE = "mil.health.sdd.nearbyclient2.ADVERTISE_MESSAGE";
    public static final String EXTRA_ADVERTISE_MESSAGE_STRING = "user_button";
    public static final String TAG = "MainActivity";
    public static final String EXTRA_MESSAGE = "mil.health.sdd.nearbyclient2.MESSAGE";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    /** Called when the user taps the Advertise button */
    public void advertiseCA(View view) {
        Intent intent = new Intent(this, AdvertiseCAActivity.class);
        intent.putExtra(EXTRA_ADVERTISE_MESSAGE, EXTRA_ADVERTISE_MESSAGE_STRING);
        startActivity(intent);
    }

    public void setupCertificates(View view) {
        Intent intent = new Intent(this, PKIActivity.class);
        startActivity(intent);
    }

    public void deleteCertificates(View view) {
        CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename));
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
