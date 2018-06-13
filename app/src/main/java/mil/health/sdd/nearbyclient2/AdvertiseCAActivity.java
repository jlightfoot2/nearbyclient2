package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.View;

import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AdvertisingOptions;
import com.google.android.gms.nearby.connection.ConnectionInfo;
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback;
import com.google.android.gms.nearby.connection.ConnectionResolution;
import com.google.android.gms.nearby.connection.ConnectionsClient;
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
    private ConnectionsClient connectionsClient;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_advertise_ca);
        connectionsClient = Nearby.getConnectionsClient(this);
        startAdvertising();
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

        stopAdvertisingActivity();
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
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
                    Log.i(TAG, "onConnectionInitiated: accepting connection");
                    connectionsClient.acceptConnection(endpointId, payloadCallback);
//                    opponentName = connectionInfo.getEndpointName();
                }

                @Override
                public void onConnectionResult(String endpointId, ConnectionResolution result) {
                    if (result.getStatus().isSuccess()) {
                        Log.i(TAG, "onConnectionResult: connection successful");

                        connectionsClient.stopDiscovery();
                        connectionsClient.stopAdvertising();

//                        opponentEndpointId = endpointId;
//                        setOpponentName(opponentName);
//                        setStatusText(getString(R.string.status_connected));
//                        setButtonState(true);
                    } else {
                        Log.i(TAG, "onConnectionResult: connection failed");
                    }
                }

                @Override
                public void onDisconnected(String endpointId) {
                    Log.i(TAG, "onDisconnected: disconnected from the opponent");
                    //resetGame();
                }
            };

            private final PayloadCallback payloadCallback =
            new PayloadCallback() {
                @Override
                public void onPayloadReceived(String endpointId, Payload payload) {
//                    opponentChoice = GameChoice.valueOf(new String(payload.asBytes(), UTF_8));
                    Log.i(TAG, "onPayloadReceived called");
                }

                @Override
                public void onPayloadTransferUpdate(String endpointId, PayloadTransferUpdate update) {
                    Log.i(TAG, "onPayloadTransferUpdate called");
                    if (update.getStatus() == PayloadTransferUpdate.Status.SUCCESS /*&& myChoice != null && opponentChoice != null*/) {
//                        finishRound();
                    }
                }
            };
}
