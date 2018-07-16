package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ListView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class CertFilesActivity extends AppCompatActivity implements FileListAdapter.OnGetViewListener {
    public static final String TAG = "CertFilesActivity";
    private File pkiDir;
    private File signedDir;
    private FileListAdapter mFileListAdapter;
    private ListView mListView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cert_files);
        pkiDir = getPublicAlbumStorageDir(CSRFilesActivity.PKI_DIR_NAME);
        signedDir = new File(pkiDir,CSRFilesActivity.PKI_SIGN_CERTS_DIR_NAME);
        mListView = (ListView) findViewById(R.id.dynamicCertsList);
        loadFiles();
    }


    private void loadFiles(){
        ArrayList<FileListItem> filesList = getFileList();

        Log.v(TAG,"Checkbox items length: " +  filesList.size());

        mFileListAdapter = new FileListAdapter(this,filesList,R.layout.file_list_item);

        mListView.setAdapter(mFileListAdapter);

    }

    public void onGetView(int position, List<FileListItem> fileList, View view){
        CheckBox fileCheckbox = view.findViewById(R.id.checkBoxFile);
        FileListItem fli = fileList.get(position);
        fileCheckbox.setText(fli.getName());
        fileCheckbox.setChecked(false);
        fileCheckbox.setText(fli.getName());
        fileCheckbox.setBackgroundColor(Color.TRANSPARENT);


    }

    public void sendClick(View view){
        Button fileCheckbox = (Button) view.findViewById(R.id.checkBoxFile);
        Log.v(TAG,"sendClick");
        notifyUser("CLICK!!!!");
    }
    private void notifyUser(String msg){

        Context context = getApplicationContext();
        CharSequence text = msg;
        int duration = Toast.LENGTH_SHORT;

        Toast toast = Toast.makeText(context, text, duration);
        toast.show();
    }
    private ArrayList<FileListItem> getFileList(){
        ArrayList<FileListItem> filesList = new ArrayList<>();
        File[] files = signedDir.listFiles();


        for (int i=0; i< files.length; i++)
        {
            if(!files[i].isDirectory()) {
                filesList.add(new FileListItem(files[i].getName()));
            }
        }

        return filesList;
    }

    public File getPublicAlbumStorageDir(String albumName) {
        // Get the directory for the user's public pictures directory.
        File csrDir = new File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOCUMENTS), albumName);
        if (!csrDir.mkdirs()) {
            Log.e(TAG, "Directory not created");
        }

        File signedDir = new File(csrDir, CSRFilesActivity.PKI_SIGN_CERTS_DIR_NAME);
        if(!signedDir.mkdirs()){
            Log.e(TAG, "Signed cert Directory not created");
        }

        return csrDir;
    }
}
