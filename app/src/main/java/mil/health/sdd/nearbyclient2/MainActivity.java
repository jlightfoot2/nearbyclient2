package mil.health.sdd.nearbyclient2;

import android.content.Intent;
import android.os.Bundle;
import android.app.Activity;
import android.view.View;

public class MainActivity extends Activity {
    public static final String EXTRA_ADVERTISE_MESSAGE = "mil.health.sdd.nearbyclient2.ADVERTISE_MESSAGE";
    public static final String EXTRA_ADVERTISE_MESSAGE_STRING = "user_button";
    public static final String TAG = "MainActivity";
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
}
