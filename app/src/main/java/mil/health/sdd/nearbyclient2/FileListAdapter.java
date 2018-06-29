package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;

import java.util.ArrayList;
import java.util.List;

public class FileListAdapter extends ArrayAdapter<FileListItem> {

    private Context mContext;
    private List<FileListItem> filesList = new ArrayList<>();

    public FileListAdapter(Context context, ArrayList<FileListItem> list){
        super(context, 0 , list);
        mContext = context;
        filesList = list;
    }

    @NonNull
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        return
    }
}
