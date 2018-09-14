package mil.health.sdd.nearbyclient2.adapters;

import android.app.Activity;
import android.support.annotation.NonNull;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;

import java.util.ArrayList;
import java.util.List;

import mil.health.sdd.nearbyclient2.FileListItem;

public class FileListAdapter extends ArrayAdapter<FileListItem> {
    private final String TAG = "FileListAdapter";
    private Activity mContext;
    private List<FileListItem> filesList = new ArrayList<>();
    private ArrayList<String> selectedFiles = new ArrayList<String>();
    private int layoutListId;
    private OnGetViewListener mViewListener;

    public FileListAdapter(Activity context, ArrayList<FileListItem> list, int layoutListId){
        super(context, 0 , list);
        mContext = context;
        mViewListener = (OnGetViewListener) context;
        filesList = list;
        this.layoutListId = layoutListId;
    }

    @NonNull
    @Override
    public View getView(final int position, View convertView, ViewGroup parent) {
//        Log.v(TAG,"FileListAdapter.getView called");
        View listItem = convertView;
        if(listItem == null)
            listItem = LayoutInflater.from(mContext).inflate(layoutListId,parent,false);

        final FileListItem currentFile = filesList.get(position);
        mViewListener.onGetView(position,filesList,listItem);

//        CheckBox fileCheckbox = (CheckBox)listItem.findViewById(R.id.checkBoxCSRFile);
//        Button fileSignButton = listItem.findViewById(R.id.buttonSignCSR);
//        fileSignButton.setVisibility(View.INVISIBLE);
//        fileCheckbox.setChecked(false);
//        fileCheckbox.setText(currentFile.getName());
//        fileCheckbox.setBackgroundColor(Color.TRANSPARENT);


//        fileCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
//            @Override
//            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
//                if (isChecked) {
//                    selectedFiles.add(buttonView.getText().toString());
//                }else{
//                    selectedFiles.remove(buttonView.getText().toString());
//                }
//                Log.v(TAG,selectedFiles.toString());
//            }
//        });

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

    public interface OnGetViewListener{
        public void onGetView(int position, List<FileListItem> list, View convertView);
    }
}
