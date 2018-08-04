package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Advertises a CA x508 signing service via NSD which clients can discover in order to submit CSRs
 *
 */
public class NSDActivity extends AppCompatActivity {

    private static final String TAG = "AppCompatActivity";
    NsdManager.RegistrationListener mRegistrationListener;
    ServerSocket mServerSocket;
    int mLocalPort;
    String mServiceName;
    boolean socketCreated = false;
    NsdManager mNsdManager;
    Thread serverThread = null;
    private ServerSocketHandler mServerHandler;
    private Thread mServerSocketThread;
    private static final int SERVER_SOCKET_STARTED = 1;
    private static final int SERVER_CLIENT_ACCEPTED = 2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nsd);
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.v(TAG,"onResume");
        mServerHandler = new ServerSocketHandler(this);
        mServerSocketThread = new Thread(new ServerThread());
        mServerSocketThread.start();
    }

    @Override
    protected void onStart() {

//        try {
//            this.generateJWE();
//        } catch (Exception e) {
//            Log.e(TAG,"JWE Exception",e);
//        }

        super.onStart();
    }
    @Override
    protected void onStop() {
        tearDownNSD();
        super.onStop();
    }




    private void tearDownNSD(){
        if(mNsdManager != null){
            try {
                mServerSocketThread.interrupt();
                mServerSocket.close();//TODO
            } catch (IOException e) {
                Log.e(TAG,"ServerSocket.close",e);
            }
            mNsdManager.unregisterService(mRegistrationListener);
        }

    }

    private void generateJWE() throws NoSuchAlgorithmException, JOSEException {
        // Generate symmetric 128 bit AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

        // Set the plain text
        Payload payload = new Payload("Hello world!");

        // Create the JWE object and encrypt it
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new DirectEncrypter(key));

        String jweString = jweObject.serialize();
        Log.v(TAG,"JWE Token: " + jweString);
    }


//    public void startService(View view){
//
//
//        try {
//            registerService(mLocalPort);
//            socketCreated = true;
//        } catch (IOException e) {
//            Log.e(TAG,"Server Socket issue",e);
//            socketCreated = false;
//        }
//    }

    public void startService(){
        Log.v(TAG,"startService with port: " + mLocalPort);
        registerService(mLocalPort);
        socketCreated = true;
    }


    private void registerService(int port){
        // Create the NsdServiceInfo object, and populate it.
        setupRegistrationListener();
        NsdServiceInfo serviceInfo = new NsdServiceInfo();

        // The name is subject to change based on conflicts
        // with other services advertised on the same network.
        serviceInfo.setServiceName("IoTCertEnroll");
        serviceInfo.setServiceType("_certEnroll._tcp");
        serviceInfo.setPort(port);

        mNsdManager = (NsdManager) this.getSystemService(Context.NSD_SERVICE);

        mNsdManager.registerService(
                serviceInfo, NsdManager.PROTOCOL_DNS_SD, mRegistrationListener);
    }

    public void setupRegistrationListener() {
        mRegistrationListener = new NsdManager.RegistrationListener() {

            @Override
            public void onServiceRegistered(NsdServiceInfo NsdServiceInfo) {
                // Save the service name. Android may have changed it in order to
                // resolve a conflict, so update the name you initially requested
                // with the name Android actually used.
                mServiceName = NsdServiceInfo.getServiceName();
                Log.v(TAG,"onServiceRegistered called");
                Log.v(TAG,"Service Name: " + mServiceName);
            }

            @Override
            public void onRegistrationFailed(NsdServiceInfo serviceInfo, int errorCode) {
                // Registration failed! Put debugging code here to determine why.
                Log.v(TAG,"onRegistrationFailed: registration failed! Put debugging code here to determine why");
            }

            @Override
            public void onServiceUnregistered(NsdServiceInfo arg0) {
                // Service has been unregistered. This only happens when you call
                // NsdManager.unregisterService() and pass in this listener.
                Log.v(TAG,"onServiceUnregistered: Service has been unregistered.");
            }

            @Override
            public void onUnregistrationFailed(NsdServiceInfo serviceInfo, int errorCode) {
                // Unregistration failed. Put debugging code here to determine why.
                Log.v(TAG,"onUnregistrationFailed: Unregistration failed. Put debugging code here to determine why.");
            }
        };
    }
    class ServerThread implements Runnable {

        public void run() {
            Socket socket = null;
            Log.v(TAG,"ServerThread run");
            try {
                mServerSocket = new ServerSocket(0);
                mLocalPort = mServerSocket.getLocalPort();
                mServerHandler.sendEmptyMessage(SERVER_SOCKET_STARTED);
            } catch (IOException e) {
                Log.e(TAG,"ServerThread Exception",e);
            }

            while (!Thread.currentThread().isInterrupted()) {
                if(mServerSocket.isClosed()){
                    return;
                }
                try {

                    socket = mServerSocket.accept();
                    mServerHandler.sendEmptyMessage(SERVER_CLIENT_ACCEPTED);

                    CommunicationThread commThread = new CommunicationThread(socket);
                    new Thread(commThread).start();

                } catch (IOException e) {
                    Log.e(TAG,"ServerThread Client Socket Exception",e);
                }
            }
        }
    }

    class CommunicationThread implements Runnable {

        private Socket clientSocket;

        private BufferedReader input;

        public CommunicationThread(Socket clientSocket) {

            this.clientSocket = clientSocket;

            try {

                this.input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));

            } catch (IOException e) {
                e.printStackTrace();
                Log.e(TAG,"CommunicationThread: Input Error",e);
            }
        }

        public void run() {

            while (!Thread.currentThread().isInterrupted()) {

                try {

                    String read = input.readLine();
                    Log.v(TAG,"CommunicationThread.run readline");
//                    serverStartHandler.post(new updateUIThread(read));

                } catch (IOException e) {
                    Log.e(TAG,"CommunicationThread: IOException readline",e);
                }
            }
        }

    }

    private static class ServerSocketHandler extends Handler {
        private final WeakReference<NSDActivity> mActivity;

        public ServerSocketHandler(NSDActivity activity){
            mActivity = new WeakReference<NSDActivity>(activity);
        }

        @Override
        public void handleMessage(Message msg) {
                NSDActivity activity = mActivity.get();
                Log.v(TAG,"ServerSocketHandler.handleMessage");
                if(activity != null){
                    if (msg.what == SERVER_SOCKET_STARTED){
                        Log.v(TAG,"ServerSocketHandler: SERVER_SOCKET_STARTED");
                        activity.startService();
                    }
                }
        }
    }


}
