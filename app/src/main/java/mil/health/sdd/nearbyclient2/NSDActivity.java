package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.Intent;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
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

    private static final String TAG = "NSDActivity";
    NsdManager.RegistrationListener mRegistrationListener;
    ServerSocket mServerSocket;
    int mLocalPort;
    String mServiceName;
    boolean socketCreated = false;
    NsdManager mNsdManager;
    Thread serverThread = null;
    private ServerSocketHandler mServerHandler;
    private JWEHandler mJWEHandler;
    private Thread mServerSocketThread;
    private Thread mJWECreateThread;
    private static final int SERVER_SOCKET_STARTED = 1;
    private static final int SERVER_CLIENT_ACCEPTED = 2;
    private static final int JWE_SECRET_CREATED = 3;
    private CAPreference mCaPreference;
    private String keyStoreAlias;
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
        mJWEHandler = new JWEHandler(this);
        keyStoreAlias = getString(R.string.android_key_store_alias);
        mCaPreference = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
    }

    @Override
    protected void onStart() {

//        try {
//            this.generateJWE();
//        } catch (Exception e) {
//            Log.e(TAG,"JWE Exception",e);
//        }


        Button buttonEnrollDevices =  findViewById(R.id.buttonEnrollNSDClients);
        buttonEnrollDevices.setVisibility(View.INVISIBLE);
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
                mServerSocket.close();//TODO (forgot what I was TODO)
            } catch (IOException e) {
                Log.e(TAG,"ServerSocket.close",e);
            }
            mNsdManager.unregisterService(mRegistrationListener);
        }

    }

    private void sendTokenEmail(String secret){
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("message/rfc822");
        i.putExtra(Intent.EXTRA_EMAIL  , new String[]{"jack.lightfoot@tee2.org"});
        i.putExtra(Intent.EXTRA_SUBJECT, "test key");
        i.putExtra(Intent.EXTRA_TEXT   , secret);
        try {
            startActivity(Intent.createChooser(i, "Send mail..."));
        } catch (android.content.ActivityNotFoundException ex) {
            Toast.makeText(NSDActivity.this, "There are no email clients installed.", Toast.LENGTH_SHORT).show();
        }
    }


    public void createSecret(View view){
        mJWECreateThread = new Thread(new JWEKeyWrapThread());
        mJWECreateThread.start();
    }

    public void startService(View view){
        mServerSocketThread = new Thread(new ServerThread());
        mServerSocketThread.start();
    }

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

    public void showEnrollmentOptions(String secretKey){
        Button buttonEnrollDevices =  findViewById(R.id.buttonEnrollNSDClients);
        buttonEnrollDevices.setVisibility(View.VISIBLE);
        TextView secretText = findViewById(R.id.textViewSecret);
        sendTokenEmail(secretKey);
        secretText.setText(secretKey);
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
    class JWEKeyWrapThread implements Runnable {

        public void run() {
            // Generate symmetric 128 bit AES key
            Payload payload = new Payload("Hello world KW!");
            JWEAlgorithm alg = JWEAlgorithm.A128KW;
            EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;


            JWEObject jwe = new JWEObject(
                    new JWEHeader(alg, encryptionMethod),
                    payload);

            KeyGenerator keyGen = null;
            try {
                keyGen = KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            keyGen.init(128);

            SecretKey key = keyGen.generateKey();

            try {
                jwe.encrypt(new AESEncrypter(key));
            } catch (JOSEException e) {
                e.printStackTrace();
            }

            String jweString = jwe.serialize();
            String keyString = null;
            try {
                keyString = new String(key.getEncoded(),"UTF-8");
            } catch (UnsupportedEncodingException e) {
                Log.e(TAG,"UnsupportedEncodingException",e);
            }
            Log.v(TAG,"JWE secret base64: " + Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP));
            Log.v(TAG,"JWE secret string: " + keyString);
            Log.v(TAG,"JWE Token: " + jweString);
            Message jweMessage = mJWEHandler.obtainMessage(JWE_SECRET_CREATED, new JWESecretMessageObject(Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP)));
            mJWEHandler.sendMessage(jweMessage);
        }
    }

//    class JWEThread implements Runnable {
//
//        public void run() {
//            // Generate symmetric 128 bit AES key
//            KeyGenerator keyGen = null;
//            try {
//                keyGen = KeyGenerator.getInstance("AES");
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            }
//            keyGen.init(128);
//            SecretKey key = keyGen.generateKey();
//            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
//
//            // Set the plain text
//            Payload payload = new Payload("Hello world!");
//
//            // Create the JWE object and encrypt it
//            JWEObject jweObject = new JWEObject(header, payload);
//            try {
//                jweObject.encrypt(new DirectEncrypter(key));
//            } catch (JOSEException e) {
//                e.printStackTrace();
//            }
//
//            String jweString = jweObject.serialize();
//            String keyString = null;
//            try {
//                keyString = new String(key.getEncoded(),"UTF-8");
//            } catch (UnsupportedEncodingException e) {
//                Log.e(TAG,"UnsupportedEncodingException",e);
//            }
//            Log.v(TAG,"JWE secret base64: " + Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP));
//            Log.v(TAG,"JWE secret string: " + keyString);
//            Log.v(TAG,"JWE Token: " + jweString);
//            Message jweMessage = mJWEHandler.obtainMessage(JWE_SECRET_CREATED, new JWESecretMessageObject(Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP)));
//            mJWEHandler.sendMessage(jweMessage);
//        }
//    }

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
                    Log.v(TAG,"incomming: " + read);
//                    serverStartHandler.post(new updateUIThread(read));
                    return;

                } catch (IOException e) {
                    Log.e(TAG,"CommunicationThread: IOException readline",e);
                }
            }
        }

    }

    private static class JWESecretMessageObject {
        private String secret;

        public JWESecretMessageObject(String secret){
            this.secret = secret;
        }

        public String getSecret(){
            return this.secret;
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

    private static class JWEHandler extends Handler {
        private final WeakReference<NSDActivity> mActivity;

        public JWEHandler(NSDActivity activity){
            mActivity = new WeakReference<NSDActivity>(activity);
        }

        @Override
        public void handleMessage(Message msg) {
            NSDActivity activity = mActivity.get();
            Log.v(TAG,"JWEHandler.handleMessage");
            if(activity != null){
                if (msg.what == JWE_SECRET_CREATED){
                    JWESecretMessageObject secretOb = (JWESecretMessageObject) msg.obj;
                    Log.v(TAG,"JWEHandler: JWE_SECRET_CREATED");
                    activity.showEnrollmentOptions(secretOb.getSecret());
                }
            }
        }
    }


}
