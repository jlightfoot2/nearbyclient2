package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AdvertisingOptions;
import com.google.android.gms.nearby.connection.ConnectionInfo;
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback;
import com.google.android.gms.nearby.connection.ConnectionResolution;
import com.google.android.gms.nearby.connection.ConnectionsClient;
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes;
import com.google.android.gms.nearby.connection.Payload;
import com.google.android.gms.nearby.connection.PayloadCallback;
import com.google.android.gms.nearby.connection.PayloadTransferUpdate;
import com.google.android.gms.nearby.connection.Strategy;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

public class AdvertiseCAActivity extends Activity {
    public static final String SERVICE_ID = "mil.health.sdd.nearbyclient2.CA_SYSTEM";
    private static final Strategy STRATEGY = Strategy.P2P_STAR;
    public static final String TAG = "AdvertiseCAActivity";
    public String mAuthenticationToken = null;
    private ConnectionsClient connectionsClient;
    public String mEndPointId = null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advertise_ca);
        connectionsClient = Nearby.getConnectionsClient(this);
        startAdvertising();
        Log.v(TAG, "onCreate");
    }

    @Override
    protected void onStop() {
        stopAdvertisingActivity();
        super.onStop();
    }

    private void stopAdvertisingActivity(){
        connectionsClient.stopAdvertising();
        connectionsClient.stopAllEndpoints();
    }

    public void stopAdvertising(View view){
        Log.v(TAG, "user::stopAdvertising");
        stopAdvertisingActivity();
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }

    public void acceptConnection(View view){
        Log.v(TAG, "user::acceptConnection");
        if(!mEndPointId.isEmpty()){
            connectionsClient.acceptConnection(mEndPointId, payloadCallback);
        }
    }

    private void startAdvertising() {
        // startAdvertising https://developers.google.com/android/reference/com/google/android/gms/nearby/connection/ConnectionsClient#startAdvertising(java.lang.String,%20java.lang.String,%20com.google.android.gms.nearby.connection.ConnectionLifecycleCallback,%20com.google.android.gms.nearby.connection.AdvertisingOptions)

        Nearby.getConnectionsClient(this).startAdvertising(
                "IoT CA Device",
                SERVICE_ID,
                mConnectionLifecycleCallback,
                new AdvertisingOptions(STRATEGY))
                .addOnSuccessListener(
                        new OnSuccessListener<Void>() {
                            @Override
                            public void onSuccess(Void unusedResult) {
                                // We're advertising!
                                Log.v(TAG,"We're advertising!");
                            }
                        })
                .addOnFailureListener(
                        new OnFailureListener() {
                            @Override
                            public void onFailure(@NonNull Exception e) {
                                // We were unable to start advertising.
                                Log.e(TAG,"We were unable to start advertising",e);
                            }
                        });
    }

    private final ConnectionLifecycleCallback mConnectionLifecycleCallback =
            new ConnectionLifecycleCallback() {
                @Override
                public void onConnectionInitiated(String endpointId, ConnectionInfo connectionInfo) {
                    Log.v(TAG, "onConnectionInitiated: setting mAuthenticationToken");
                    mEndPointId = endpointId;
//                    opponentName = connectionInfo.getEndpointName();
                    mAuthenticationToken = connectionInfo.getAuthenticationToken();
                    EditText textConnectionHeader = (EditText) findViewById(R.id.editTextConnectionHeader);
                    textConnectionHeader.setText("Connect request from: " + mEndPointId);
                    EditText textConnectionStatus = (EditText) findViewById(R.id.editTextConnectionStatus);
                    textConnectionStatus.setText("Token: " + mAuthenticationToken);
                }

                @Override
                public void onConnectionResult(String endpointId, ConnectionResolution result) {
                    Log.v(TAG,"onConnectionResult");
                    switch (result.getStatus().getStatusCode()) {
                        case ConnectionsStatusCodes.STATUS_OK:
                            connectionsClient.stopDiscovery();
                            connectionsClient.stopAdvertising();
                            Log.v(TAG,"We're connected! Can now start sending and receiving data");
                            EditText textConnectionHeader = (EditText) findViewById(R.id.editTextConnectionHeader);
                            textConnectionHeader.setText("Success");
                            EditText textConnectionStatus = (EditText) findViewById(R.id.editTextConnectionStatus);
                            textConnectionStatus.setText("You are now connected");
                            break;
                        case ConnectionsStatusCodes.STATUS_CONNECTION_REJECTED:
                            // The connection was rejected by one or both sides.
                            Log.v(TAG,"The connection was rejected by one or both sides.");
                            break;
                        case ConnectionsStatusCodes.STATUS_ERROR:
                            // The connection broke before it was able to be accepted.
                            Log.v(TAG,"The connection broke before it was able to be accepted.");
                            break;
                    }
                }

                @Override
                public void onDisconnected(String endpointId) {
                    Log.v(TAG, "onDisconnected: disconnected from the opponent");
                    //resetGame();
                    mEndPointId = null;
                }
            };

            private final PayloadCallback payloadCallback =
            new PayloadCallback() {
                @Override
                public void onPayloadReceived(String endpointId, Payload payload) {
//                    opponentChoice = GameChoice.valueOf(new String(payload.asBytes(), UTF_8));
                    Log.v(TAG, "onPayloadReceived called");
                }

                @Override
                public void onPayloadTransferUpdate(String endpointId, PayloadTransferUpdate update) {
                    Log.v(TAG, "onPayloadTransferUpdate called");
                    if (update.getStatus() == PayloadTransferUpdate.Status.SUCCESS /*&& myChoice != null && opponentChoice != null*/) {
//                        finishRound();
                    }
                }
            };
}
