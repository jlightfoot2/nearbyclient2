package mil.health.sdd.nearbyclient2;

import android.graphics.Color;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;

import java.util.ArrayList;
import java.util.List;

public class CSRListAdapter extends ArrayAdapter<FileListItem> {
    private final String TAG = "FileListAdapter";
    private CSRFilesActivity mContext;
    private List<FileListItem> filesList = new ArrayList<>();
    private ArrayList<String> selectedFiles = new ArrayList<String>();

    public CSRListAdapter(CSRFilesActivity context, ArrayList<FileListItem> list){
        super(context, 0 , list);
        mContext = context;
        filesList = list;
    }

    @NonNull
    @Override
    public View getView(final int position, View convertView, ViewGroup parent) {
//        Log.v(TAG,"FileListAdapter.getView called");
        View listItem = convertView;
        if(listItem == null)
            listItem = LayoutInflater.from(mContext).inflate(R.layout.csr_list_item,parent,false);

        final FileListItem currentFile = filesList.get(position);

        CheckBox fileCheckbox = (CheckBox)listItem.findViewById(R.id.checkBoxCSRFile);
        Button fileSignButton = listItem.findViewById(R.id.buttonSignCSR);
        fileSignButton.setVisibility(View.INVISIBLE);
        fileCheckbox.setChecked(false);
        fileCheckbox.setText(currentFile.getName());
        fileCheckbox.setBackgroundColor(Color.TRANSPARENT);
        if(currentFile.isInpsected()){
            if(currentFile.isValid()){
                fileCheckbox.setText(currentFile.getCert());
                fileCheckbox.setBackgroundColor(Color.GREEN);
                fileSignButton.setVisibility(View.VISIBLE);
                fileSignButton.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        mContext.signCert(currentFile.getName());
                    }
                });
            } else {
                fileCheckbox.setBackgroundColor(Color.RED);
            }
        }

        fileCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    selectedFiles.add(buttonView.getText().toString());
                }else{
                    selectedFiles.remove(buttonView.getText().toString());
                }
                Log.v(TAG,selectedFiles.toString());
            }
        });

        return listItem;
    }

    public ArrayList<String> getSelectedFileNames(){
        return selectedFiles;
    }

    public FileListItem search(String searchText){
        for(int i=0; i < filesList.size(); i++) {
            FileListItem file = filesList.get(i);
            if(file.getName().equals(searchText)){
                return file;
            }
        }
        return null;
    }
}
