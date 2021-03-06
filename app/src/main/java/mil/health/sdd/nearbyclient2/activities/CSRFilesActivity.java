package mil.health.sdd.nearbyclient2.activities;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Calendar;

import mil.health.sdd.nearbyclient2.CAPreference;
import mil.health.sdd.nearbyclient2.helper.CSRHelper;
import mil.health.sdd.nearbyclient2.adapters.CSRListAdapter;
import mil.health.sdd.nearbyclient2.FileListItem;
import mil.health.sdd.nearbyclient2.R;

public class CSRFilesActivity extends Activity {
    public static final String TAG = "CSRFilesActivity";
    public static final String PKI_DIR_NAME = "MILHEALTHSDDPKI";
    public  String keyStoreAlias;
    public static final String PKI_SIGN_CERTS_DIR_NAME = "signed";
    private boolean hasDir = false;
    private File pkiDir;
    private CSRListAdapter mFileListAdapter;
    private ListView mListView;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_csr_files);
        mListView = (ListView) findViewById(R.id.dynamicCSRList);
        this.checkExternalStorage();
        keyStoreAlias = getString(R.string.android_key_store_alias);
        if(hasDir){
            Log.v(TAG,"onCreate > hasDir == true");
            loadFiles();
            CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
//            try {
//                caPreferences.testEncDec();
//            } catch (Exception e) {
//                Log.e(TAG,"FAILED: caPreferences.testEncDec()",e);
//            }
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    private void checkExternalStorage(){
        if(!this.isExternalStorageWritable()){
            notifyUser("External storage is NOT currently writable");
        } else {
            notifyUser("Is writable");
            pkiDir = this.getPublicAlbumStorageDir(PKI_DIR_NAME);
            if(pkiDir.exists()){
                hasDir = true;
                notifyUser(PKI_DIR_NAME + ": " + pkiDir.getAbsolutePath());
            } else {
                notifyUser(PKI_DIR_NAME + " does not exist");
            }
        }
    }

    private void testFileCreation() throws IOException {
        notifyUser(PKI_DIR_NAME + ": " + pkiDir.getAbsolutePath());
        Log.v(TAG,PKI_DIR_NAME + ": " + pkiDir.getAbsolutePath());
        Calendar calendar = Calendar.getInstance();
        //Returns current time in millis
        long timeSeconds = calendar.getTimeInMillis() / 1000;
        File testfile = new File(pkiDir, timeSeconds + "myData.txt");
        FileOutputStream f = new FileOutputStream(testfile);
        PrintWriter pw = new PrintWriter(f);
        pw.println("Hi , How are you");
        pw.println("Hello World");
        pw.flush();
        pw.close();
        f.close();
    }

    private ArrayList<FileListItem> getFileList(){
        ArrayList<FileListItem> filesList = new ArrayList<>();
        File[] files = pkiDir.listFiles();

        notifyUser(files.length + " CSRs available");

        for (int i=0; i< files.length; i++)
        {
            if(!files[i].isDirectory()) {
                filesList.add(new FileListItem(files[i].getName()));
            }
        }

        return filesList;
    }

    private void loadFiles(){
        ArrayList<FileListItem> filesList = getFileList();

        Log.v(TAG,"Checkbox items length: " +  filesList.size());

        mFileListAdapter = new CSRListAdapter(this,filesList);

        mListView.setAdapter(mFileListAdapter);


    }
    private void notifyUser(String msg){

        Log.v(TAG,msg);
        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }

    public void deleteFiles(View view){
        ArrayList<String> filenames = mFileListAdapter.getSelectedFileNames();
        for(int i=0; i<filenames.size(); i++) {
            String fileName = filenames.get(i);
            File file = new File(pkiDir,fileName);
            if(file.exists()){
               Log.v(TAG,fileName + " exists");
                file.delete();
            }
        }
        mFileListAdapter.clear();
        mFileListAdapter.addAll(getFileList());
        mFileListAdapter.notifyDataSetChanged();

    }

    private PKCS10CertificationRequest loadCSR(File file){
        PKCS10CertificationRequest csr = null;
        try {
            csr = getCSRFromPem(file);

        } catch (IOException e) {
            Log.e(TAG,"Failed to load cert as PEM",e);
        }
        if(csr == null){
            try {
                csr = new PKCS10CertificationRequest(fileToBytes(file)); //DerFormat
            } catch (IOException e) {
                Log.e(TAG,"Failed to load cert as DER",e);
            }
        }
        return csr;
    }

    public void signCert(String filename){
        CAPreference caPreferences = new CAPreference(this,getString(R.string.preference_pki_filename),keyStoreAlias);
        FileListItem foundFile = mFileListAdapter.search(filename);
        File file = new File(pkiDir,filename);
        Log.v(TAG,"Signed cert called for file: " + filename);

        try {

            PKCS10CertificationRequest csrReq = loadCSR(file);
            if(caPreferences.isSetup()){
                String extension = "";

                int i = filename.lastIndexOf('.');
                if (i > 0) {
                    extension = filename.substring(i+1);
                }
                String certFileName = filename.replace(extension,"crt");
                String issuerCNString = String.format(PKIActivity.CA_CN_PATTERN, PKIActivity.CA_CN);
                X509Certificate signedClientCert = CSRHelper.sign(csrReq,caPreferences.getKeyPair(),issuerCNString);
                File signedDir = new File(pkiDir, PKI_SIGN_CERTS_DIR_NAME);
                File signedCert = new File(signedDir, certFileName);
                signedCert.createNewFile();
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(signedCert));
                bos.write(signedClientCert.getEncoded());
                bos.flush();
                bos.close();
            }
        } catch (IOException e) {
            Log.e(TAG,"CSR Signing error 1",e);
        } catch (CertificateException e) {
            Log.e(TAG,"CSR Signing error 2",e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG,"CSR Signing error 3",e);
        } catch (InvalidKeySpecException e) {
            Log.e(TAG,"CSR Signing error 4",e);
        } catch (OperatorCreationException e) {
            Log.e(TAG,"CSR Signing error 5",e);
        } catch (NoSuchProviderException e) {
            Log.e(TAG,"CSR Signing error 6",e);
        } catch (CAPreference.CAPreferencePrivateKeyDecryptException e) {
            Log.e(TAG,"CSR Signing error 7",e);
        }
    }

    private PKCS10CertificationRequest getCSRFromPem(File file) throws IOException {
        PEMParser parser = new PEMParser(new FileReader(file));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
        return csr;
    }

    public void inspectFiles(View view){
        ArrayList<String> filenames = mFileListAdapter.getSelectedFileNames();
        for(int i=0; i<filenames.size(); i++) {
            String fileName = filenames.get(i);
            File file = new File(pkiDir,fileName);
            if(file.exists()){
                Log.v(TAG,fileName + " exists");
                FileListItem foundFile = mFileListAdapter.search(fileName);
                foundFile.setInpsected(true);
                if(foundFile != null){
                    try {
                        PKCS10CertificationRequest csrReq = loadCSR(file);
                        if(csrReq == null){
                            foundFile.setValid(false);
                        }else{
                            String certString = printCSRInfo(csrReq);
                            foundFile.setValid(true);
                            foundFile.setCert(fileName + " \n" +certString);
                        }

                    } catch (IOException e) {
                        foundFile.setValid(false);
                        Log.e(TAG,"Could not load as a csr",e);
                    }
                } else {
                   Log.v(TAG,"Could not find file with mFileListAdapter.search: " + fileName);
                }

            }
        }
        mFileListAdapter.notifyDataSetChanged();
    }

    private String printCSRInfo(PKCS10CertificationRequest certRequest) throws IOException {
        X500Name x500Name = certRequest.getSubject();
//        RDN email = x500Name.getRDNs(BCStyle.EmailAddress)[0];
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        RDN organization = x500Name.getRDNs(BCStyle.O)[0];
        RDN organizationUnit = x500Name.getRDNs(BCStyle.OU)[0];
        RDN country = x500Name.getRDNs(BCStyle.C)[0];
        RDN locality = x500Name.getRDNs(BCStyle.L)[0];
        String cnStr = cn.getFirst().getValue().toString();
        String organizationStr = organization.getFirst().getValue().toString();
        String organizationUnitStr = organizationUnit.getFirst().getValue().toString();
        String countryStr = country.getFirst().getValue().toString();
        String localityStr = locality.getFirst().getValue().toString();

        String certString = String.format("CN: %s\nOrg: %s\nUnit: %s\nCountry: %s\nLocality: %s\n",
                cnStr,organizationStr,organizationUnitStr,countryStr,localityStr);
        Log.v(TAG,certString);
        return certString;
    }
    private byte[] fileToBytes(File file) throws IOException {

        //init array with file length
        byte[] bytesArray = new byte[(int) file.length()];

        FileInputStream fis = new FileInputStream(file);
        fis.read(bytesArray); //read file into bytes[]
        fis.close();

        return bytesArray;
    }


    public boolean isExternalStorageWritable() {
        String state = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(state)) {
            return true;
        }
        return false;
    }

    /* Checks if external storage is available to at least read */
    public boolean isExternalStorageReadable() {
        String state = Environment.getExternalStorageState();
        if (Environment.MEDIA_MOUNTED.equals(state) ||
                Environment.MEDIA_MOUNTED_READ_ONLY.equals(state)) {
            return true;
        }
        return false;
    }

    public File getPublicAlbumStorageDir(String albumName) {
        // Get the directory for the user's public pictures directory.
        File csrDir = new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOCUMENTS), albumName);
        if (!csrDir.mkdirs()) {
            Log.e(TAG, "Directory not created");
        }

        File signedDir = new File(csrDir, PKI_SIGN_CERTS_DIR_NAME);
        if(!signedDir.mkdirs()){
            Log.e(TAG, "Signed cert Directory not created");
        }

        return csrDir;
    }

}