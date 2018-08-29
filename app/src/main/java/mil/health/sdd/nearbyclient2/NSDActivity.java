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
    private Thread mServerSocketThread;
    private Thread mTokenCreateThread;

    private String mCSRequest;
    private static final int ACTIVITY_CSR_REQUEST = 1;

    private static final int SERVER_SOCKET_STARTED = 1;
    private static final int SERVER_CLIENT_ACCEPTED = 2;
    private static final int JWE_X509_TOKEN_CREATED = 3;
    private static final int JWE_TOKEN_RECEIVED = 4;

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
        super.onStop();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(requestCode == ACTIVITY_CSR_REQUEST){
            if(resultCode == RESULT_OK){
                Log.v(TAG,"SUCCESS: onActivityResult: ACTIVITY_CSR_REQUEST");
                //TODO extract base64 cert, put in token and return it

                Bundle clientBundle = data.getBundleExtra(CSRSignActivity.EXTRA_MESSAGE);
                String x509cert = clientBundle.getString("cert");
                mSharedKey = clientBundle.getString("shared_key");
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

    public void startCertificateReturn(){

    }


    public void startScan(View view){
        Intent intent = new Intent(this,CodeScanActivity.class);
        startActivity(intent);
    }

    public void handleToken(JWETokenMessageObject secretOb){
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
                    JWETokenMessageObject secretOb = (JWETokenMessageObject) msg.obj;
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
            Log.v(TAG,"JWEDecryptHandler.handleMessage");
            if(activity != null){
                if(msg.what == JWE_X509_TOKEN_CREATED){
                    Log.v(TAG,"x509 token created and sent to handler")
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

    private static class JWETokenMessageObject {
        private String token;
        private String clientIp;
        private int clientPort;

        public JWETokenMessageObject(String token, String clientIp, int clientPort){
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

//            KeyGenerator keyGen = null;
//            try {
//                keyGen = KeyGenerator.getInstance("AES");
//            } catch (NoSuchAlgorithmException e) {
//                e.printStackTrace();
//            }
//            keyGen.init(128);
//
//            SecretKey key = keyGen.generateKey();

            try {
                jwe.encrypt(new AESEncrypter(key));
            } catch (JOSEException e) {
                e.printStackTrace();
            }

            String jweString = jwe.serialize();
//            String keyString = null;
//            try {
//                keyString = new String(key.getEncoded(),"UTF-8");
//            } catch (UnsupportedEncodingException e) {
//                Log.e(TAG,"UnsupportedEncodingException",e);
//            }
            Log.v(TAG,"JWE secret base64: " + Base64.encodeToString(key.getEncoded(),Base64.NO_WRAP));
//            Log.v(TAG,"JWE secret string: " + keyString);
            Log.v(TAG,"JWE Token: " + jweString);

            Message jweMessage = mJWEDecryptHandler.obtainMessage(JWE_X509_TOKEN_CREATED, new JWE509TokenMessage(jweString));
            mJWEDecryptHandler.sendMessage(jweMessage);
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

        public CommunicationThread(Socket clientSocket) {

            this.clientSocket = clientSocket;

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
                    String clientIp = clientSocket.getInetAddress().toString();
                    int clientPort = clientSocket.getPort();
                    Message jweMessage = mJWEDecryptHandler.obtainMessage(JWE_TOKEN_RECEIVED, new JWETokenMessageObject(encToken,clientIp,clientPort));
                    mJWEDecryptHandler.sendMessage(jweMessage);
                    this.input.close(); //TODO will this cause socket to close?
                    return;
                } catch (IOException e) {
                    Log.e(TAG,"CommunicationThread: IOException readline",e);
                }
            }
        }

    }

    private void send509Token(String token, InetAddress address, int portNum) throws IOException {
        try (
            Socket clientSocket = new Socket(address, portNum);
            PrintWriter out =
                    new PrintWriter(clientSocket.getOutputStream(), true);

        ){
            out.print(token); //send the token
        }


    }

//    class Socket509Send implements Runnable {
//
//        private InetAddress address;
//        private int portNum;
//        private String token;
//
//        public Socket509Send(String token, InetAddress address, int portNum) {
////            InetAddress inetAddress = InetAddress.getByName(address);
//            this.portNum = portNum;
//            this.address = address;
//            this.token = token;
//        }
//
//        public void run() {
//            try {
//                Socket clientSocket = new Socket(this.address, this.portNum);
//                while (!Thread.currentThread().isInterrupted()) {
//                    PrintWriter out =
//                            new PrintWriter(clientSocket.getOutputStream(), true);
//                    out.print(this.token);
//                }
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//
//        }
//
//    }
}
