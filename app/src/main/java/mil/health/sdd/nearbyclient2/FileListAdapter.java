package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;

import java.util.ArrayList;
import java.util.List;

public class FileListAdapter extends ArrayAdapter<FileListItem> {
    private final String TAG = "FileListAdapter";
    private Context mContext;
    private List<FileListItem> filesList = new ArrayList<>();
    private ArrayList<String> selectedFiles = new ArrayList<String>();

    public FileListAdapter(Context context, ArrayList<FileListItem> list){
        super(context, 0 , list);
        mContext = context;
        filesList = list;
    }

    @NonNull
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View listItem = convertView;
        if(listItem == null)
            listItem = LayoutInflater.from(mContext).inflate(R.layout.csr_list_item,parent,false);

        FileListItem currentFile = filesList.get(position);

        CheckBox file = (CheckBox)listItem.findViewById(R.id.checkBoxCSRFile);
        file.setChecked(false);
        file.setText(currentFile.getName());
        file.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
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
}
