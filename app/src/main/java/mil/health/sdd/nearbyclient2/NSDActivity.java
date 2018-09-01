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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.AESEncrypter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Advertises a CA x508 signing service via NSD which clients can discover in order to submit CSRs
 *
 */
public class NSDActivity extends AppCompatActivity {

    private static final String TAG = "NSDActivity";
    public static final String EXTRA_MESSAGE = "mil.health.sdd.nearbyclient2.CSR";
    NsdManager.RegistrationListener mRegistrationListener;
    ServerSocket mServerSocket;
    int mLocalPort;
    String mServiceName;
    boolean socketCreated = false;
    NsdManager mNsdManager;

    private ServerSocketHandler mServerHandler;
    private JWEDecryptHandler mJWEDecryptHandler;
    private JWEEncryptHandler mJWEEncryptHandler;
    private Thread mServerSocketThread;
    private Thread mTokenCreateThread;
    private Thread mSendCertThread;
    private String mCSRequest;
    private static final int ACTIVITY_CSR_REQUEST = 1;

    private static final int SERVER_SOCKET_STARTED = 1;
    private static final int SERVER_CLIENT_ACCEPTED = 2;
    private static final int JWE_X509_TOKEN_CREATED = 3;
    private static final int JWE_TOKEN_RECEIVED = 4;

    private String remoteClientIp;
    private int remoteClientPort;

    public String mSharedKey;
    public String mClientToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nsd);
        Intent intent = getIntent();
        mSharedKey = intent.getStringExtra(CodeScanActivity.EXTRA_MESSAGE);
        TextView secretText = findViewById(R.id.textViewSecret);
        Button mScanButton = findViewById(R.id.buttonGoToScan);
        mScanButton.setVisibility(View.INVISIBLE);
        secretText.setText("Key: " + mSharedKey);
        this.startSocketService();
    }

    @Override
    protected void onResume() {
        super.onResume();

        Log.v(TAG,"onResume");
    }


    @Override
    protected void onStop() {
        mClientToken = "";
        mSharedKey = "";
        tearDownNSD();
        if(mSendCertThread != null && !mSendCertThread.isInterrupted()){
            mSendCertThread.interrupt();
            mSendCertThread = null;
        }
        super.onStop();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        Log.v(TAG,"onActivityResult");
        if(requestCode == ACTIVITY_CSR_REQUEST){
            Log.v(TAG,"requestCode == ACTIVITY_CSR_REQUEST");
            if(resultCode == RESULT_OK){
                Log.v(TAG,"SUCCESS: onActivityResult: ACTIVITY_CSR_REQUEST");
                //TODO extract base64 cert, put in token and return it

                Bundle clientBundle = data.getBundleExtra(CSRSignActivity.EXTRA_MESSAGE);
                String x509cert = clientBundle.getString("cert");
                mSharedKey = clientBundle.getString("shared_key");

                remoteClientIp = clientBundle.getString("client_ip");
                remoteClientPort = clientBundle.getInt("client_port");
                mJWEEncryptHandler = new JWEEncryptHandler(this);
                mTokenCreateThread = new Thread(new JWEEncryptThread(x509cert,mSharedKey));
                mTokenCreateThread.start();
                Log.v(TAG, "X509 cert: " + clientBundle.getString("cert"));


            } else {
                Log.v(TAG,"FAILURE: onActivityResult: ACTIVITY_CSR_REQUEST failed");
            }
        }
    }

//    public void showEnrollmentOptions(){
//        TextView secretText = findViewById(R.id.textViewSecret);
//
//        secretText.setText("Port OR Token: " + mLocalPort);
//    }

    public void tearDownNSD(){
        if(mNsdManager != null){
            try {
                mServerSocket.close();//TODO (forgot what I was TODO)
                mServerSocketThread.interrupt();
            } catch (IOException e) {
                Log.e(TAG,"ServerSocket.close",e);
            }
            Log.v(TAG,"tearDownNSD: mNsdManager.unregisterService");
            mNsdManager.unregisterService(mRegistrationListener);
            mNsdManager = null;
        }
    }

    public void startSocketService(){
        mServerHandler = new ServerSocketHandler(this);
        mJWEDecryptHandler = new JWEDecryptHandler(this);
        mServerSocketThread = new Thread(new ServerThread());
        mServerSocketThread.start();
    }


    public void startNSDService(){
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



    public void startScan(View view){
        Intent intent = new Intent(this,CodeScanActivity.class);
        startActivity(intent);
    }

    public void handleToken(JWETokenMessage secretOb){
        String sharedKeyTmp = mSharedKey;
        if(decryptToken()){
            Log.v(TAG,"Starting CSRSignActivity");
            Intent csrSignIntent = new Intent(this,CSRSignActivity.class);

//            csrSignIntent.put
            Bundle clientBundle = new Bundle();
            clientBundle.putString("csr", mCSRequest);
            clientBundle.putString("client_ip", secretOb.getClientIp());
            clientBundle.putInt("client_port", secretOb.getClientPort());
            clientBundle.putString("shared_key", sharedKeyTmp);
            csrSignIntent.putExtra(EXTRA_MESSAGE, clientBundle);

            startActivityForResult(csrSignIntent,ACTIVITY_CSR_REQUEST);
        }
    }


    public boolean decryptToken() {
        JWEObject jweObject = null;
        Log.v(TAG,"TOKEN: " + mClientToken);
        Log.v(TAG,"SHARED_KEY: " + mSharedKey);

        Payload payload = null;
        try {
            byte[] decodedKey = Base64.decode(mSharedKey,Base64.URL_SAFE);//byte[] decodedKey = Base64.decode(mSharedKey,Base64.DEFAULT); //was getting invalid key lengths with

            Log.v(TAG,"KEY_LENGTH: " + decodedKey.length);

            SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            jweObject = JWEObject.parse(mClientToken);
            jweObject.decrypt(new AESDecrypter(key));
            payload = jweObject.getPayload();
            Log.v(TAG,"PAYLOAD Decrypted!!!!");
        } catch (Exception e) {
            Log.e(TAG,"Token Decrypt Exception: ",e);
        }

        String csrRequest = "";
        mCSRequest = "";
        if(payload != null){
            csrRequest = payload.toString();
            Log.v(TAG,"payload: " + csrRequest);
            if(csrRequest.length() > 0){
                mCSRequest = csrRequest;
                return true;
            }

        } else {
            Button mScanButton = findViewById(R.id.buttonGoToScan);
            mScanButton.setVisibility(View.VISIBLE);
            Log.v(TAG,"Payload == null");
        }

        TextView secretText = findViewById(R.id.textViewSecret);

        secretText.setText("Operation failed try again");

        return false;
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
            TextView secretText = activity.findViewById(R.id.textViewSecret);
            if(activity != null){
                if (msg.what == SERVER_SOCKET_STARTED){
                    Log.v(TAG,"ServerSocketHandler: SERVER_SOCKET_STARTED");
                    activity.startNSDService();
                    secretText.setText("Advertising on PORT: " + activity.mLocalPort);
                }
            }
        }
    }

    private static class JWEDecryptHandler extends Handler {
        private final WeakReference<NSDActivity> mActivity;

        public JWEDecryptHandler(NSDActivity activity){
            mActivity = new WeakReference<NSDActivity>(activity);
        }

        @Override
        public void handleMessage(Message msg) {
            NSDActivity activity = mActivity.get();
            Log.v(TAG,"JWEDecryptHandler.handleMessage");
            if(activity != null){
                if(msg.what == JWE_TOKEN_RECEIVED){
                    JWETokenMessage secretOb = (JWETokenMessage) msg.obj;
                    Log.v(TAG,"JWEDecryptHandler: JWE_TOKEN_RECEIVED");
                    activity.mClientToken = secretOb.getToken();
                    activity.tearDownNSD();
                    activity.handleToken(secretOb);
                }
            }
        }
    }

    private static class JWEEncryptHandler extends Handler {
        private final WeakReference<NSDActivity> mActivity;

        public JWEEncryptHandler(NSDActivity activity){
            mActivity = new WeakReference<NSDActivity>(activity);
        }

        @Override
        public void handleMessage(Message msg) {
            NSDActivity activity = mActivity.get();
            Log.v(TAG,"JWEEncryptHandler.handleMessage");
            if(activity != null){
                if(msg.what == JWE_X509_TOKEN_CREATED){
                    Log.v(TAG,"x509 token created and sent to handler");
                    JWE509TokenMessage message = (JWE509TokenMessage) msg.obj;
                    try {
                        activity.send509Token(message.getToken());
                    } catch (IOException e) {
                        Log.e(TAG,"send509Token failed",e);
                    }
                }
            }
        }
    }


    private static class JWE509TokenMessage {
        private String token;

        public JWE509TokenMessage(String token){
            this.token = token;
        }

        public String getToken(){
            return this.token;
        }

    }

    private static class JWETokenMessage {
        private String token;
        private String clientIp;
        private int clientPort;

        public JWETokenMessage(String token, String clientIp, int clientPort){
            this.token = token;
            this.clientIp = clientIp;
            this.clientPort = clientPort;
        }

        public String getToken(){
            return this.token;
        }
        public String getClientIp(){
            return this.clientIp;
        }
        public int getClientPort(){
            return this.clientPort;
        }
    }


    class Socket509SendThread implements Runnable {
        private String token;
        private String remoteClientIp;
        private int remoteClientPort;

        public Socket509SendThread(String token, String remoteClientIp, int remoteClientPort) {
            this.token = token;
            this.remoteClientIp = remoteClientIp;
            this.remoteClientPort = remoteClientPort;
        }

        public void run() {
            Log.v(TAG, "Sending Token to " + remoteClientIp + " on port " + remoteClientPort);
            Log.v(TAG,remoteClientIp);
            Log.v(TAG,"Token: " + token);

            try (

                    Socket clientSocket = new Socket(InetAddress.getByName(this.remoteClientIp), this.remoteClientPort);
                    PrintWriter out =
                            new PrintWriter(clientSocket.getOutputStream(), true);

            ){
                out.println(token); //send the token
                clientSocket.close();
            } catch (UnknownHostException e) {
                Log.e(TAG,"UnknownHostException",e);
            } catch (IOException e) {
                Log.e(TAG,"IOException",e);
            }
        }
    }

    class JWEEncryptThread implements Runnable {
        private String base64Cert;
        private String key;

        public JWEEncryptThread(String base64Cert, String key){
            this.base64Cert = base64Cert;
            this.key = key;
        }

        public void run() {
            // Generate symmetric 128 bit AES key
            Payload payload = new Payload(this.base64Cert);
            JWEAlgorithm alg = JWEAlgorithm.A128KW;
            EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;


            JWEObject jwe = new JWEObject(
                    new JWEHeader(alg, encryptionMethod),
                    payload);


            byte[] keyBytes = Base64.decode(this.key,Base64.URL_SAFE);
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");


            try {
                jwe.encrypt(new AESEncrypter(key));
            } catch (JOSEException e) {
                e.printStackTrace();
            }

            String jweString = jwe.serialize();

            Log.v(TAG,"JWE secret base64: " + Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP));
            Log.v(TAG,"JWE Token: " + jweString);

            Message jweMessage = mJWEEncryptHandler.obtainMessage(JWE_X509_TOKEN_CREATED, new JWE509TokenMessage(jweString));
            mJWEEncryptHandler.sendMessage(jweMessage);
        }
    }

    class ServerThread implements Runnable {

        public void run() {
            Socket socket = null;
            Log.v(TAG,"ServerThread run");
            try {
                mServerSocket = new ServerSocket(0);
                mLocalPort = mServerSocket.getLocalPort();
                Log.v("ServerThread","Advertising on Port: " + mLocalPort);
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
                    new Thread(commThread).start();//TODO huh? why not just commThread.start()

                } catch (IOException e) {
                    Log.e(TAG,"ServerThread Client Socket Exception",e);
                }
            }
        }
    }

    class CommunicationThread implements Runnable {

        private Socket clientSocket;

        private BufferedReader input;

        private String remoteInetAddress;
        private int remotePortNum;

        public CommunicationThread(Socket clientSocket) {

            this.clientSocket = clientSocket;
            this.remoteInetAddress = this.clientSocket.getInetAddress().getHostAddress();
            Log.v(TAG,"Socket.getInetAddress().toString() == " +this.remoteInetAddress);
            this.remotePortNum = this.clientSocket.getPort();
            try {
                //Closing the returned InputStream will close the associated socket.
                this.input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));

            } catch (IOException e) {
                e.printStackTrace();
                Log.e(TAG,"CommunicationThread: Input Error",e);
            }
        }

        public void run() {
            String encToken = "";
            while (!Thread.currentThread().isInterrupted()) {

                try {

                    int value = 0;
                    while((value = input.read()) != -1){
                        encToken += (char)value;
                    }
                    Log.v(TAG,"Finished reading socket");
                    Log.v(TAG,"CommunicationThread.run readline");
                    Log.v(TAG,"token from client: " + encToken);

                    Message jweMessage = mJWEDecryptHandler.obtainMessage(JWE_TOKEN_RECEIVED, new JWETokenMessage(encToken,this.remoteInetAddress,this.remotePortNum));
                    mJWEDecryptHandler.sendMessage(jweMessage);
                    this.input.close(); //TODO will this cause socket to close?
                    return;
                } catch (IOException e) {
                    Log.e(TAG,"CommunicationThread: IOException readline",e);
                }
            }
        }

    }

    public void send509Token(String token) throws IOException {
        Log.v(TAG, "send509Token called");
        mSendCertThread = new Thread(new Socket509SendThread(token,remoteClientIp,remoteClientPort));
        mSendCertThread.start();
    }

}
