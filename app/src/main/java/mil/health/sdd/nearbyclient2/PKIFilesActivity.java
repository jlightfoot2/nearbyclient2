package mil.health.sdd.nearbyclient2;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.Toast;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Calendar;

public class PKIFilesActivity extends Activity {
    public static final String TAG = "PKIFilesActivity";
    public static final String PKI_DIR_NAME = "MILHEALTHSDDPKI";
    private boolean hasDir = false;
    private File pkiDir;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pkifiles);
        this.checkExternalStorage();
        if(hasDir){
            this.listDirFiles();
        }
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
                Log.v(TAG,PKI_DIR_NAME + ": " + pkiDir.getAbsolutePath());
                Calendar calendar = Calendar.getInstance();
                //Returns current time in millis
                long timeSeconds = calendar.getTimeInMillis() / 1000;
                File testfile = new File(pkiDir, timeSeconds + "myData.txt");
                try {
                    FileOutputStream f = new FileOutputStream(testfile);
                    PrintWriter pw = new PrintWriter(f);
                    pw.println("Hi , How are you");
                    pw.println("Hello World");
                    pw.flush();
                    pw.close();
                    f.close();
                    Log.v(TAG,"File was written");
                } catch (FileNotFoundException e) {
                    Log.e(TAG,"Could not open file for writing #1",e);
                } catch (IOException e) {
                    Log.e(TAG,"Could not open file for writing #2",e);
                }
            } else {
                notifyUser(PKI_DIR_NAME + " does not exist");
            }
        }
    }

    private void listDirFiles(){
        File[] files = pkiDir.listFiles();

        String[] newArr = new String[files.length];


        notifyUser(files.length + " CSRs available");

        for (int i=0; i< files.length; i++)
        {
            newArr[i] = files[i].getName();
        }

        Log.v(TAG,"Spinner items length: " +  files.length);



        Spinner spinner = (Spinner) findViewById(R.id.spinnerCSRs);


        ArrayAdapter<String> adapter = new ArrayAdapter<String>(
                this, android.R.layout.simple_spinner_item, newArr);

        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        spinner.setAdapter(adapter);

    }

    private void notifyUser(String msg){
//        Snackbar.make(findViewById(R.id.pkiCoordinatorLayout), msg,
//                Snackbar.LENGTH_SHORT).show(); //Relies on AppCompat so doesn't work
        Log.v(TAG,msg);
        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
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
        File file = new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOCUMENTS), albumName);
        if (!file.mkdirs()) {
            Log.e(TAG, "Directory not created");
        }
        return file;
    }

}
