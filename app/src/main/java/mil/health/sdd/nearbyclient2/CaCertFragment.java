package mil.health.sdd.nearbyclient2;


import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;


/**
 * A simple {@link Fragment} subclass.
 */
public class CaCertFragment extends Fragment {
    CaCertificateListenter mCallback;

//    public CaCertFragment() {
//        // Required empty public constructor
//    }
@Override
    public void onAttach(Context context) {
        super.onAttach(context);

        // This makes sure that the container activity has implemented
        // the callback interface. If not, it throws an exception
        try {
            mCallback = (CaCertificateListenter) context;
        } catch (ClassCastException e) {
            throw new ClassCastException(context.toString()
                    + " must implement OnHeadlineSelectedListener");
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_ca_cert, container, false);
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        // Set values for view here
        TextView tv = (TextView) view.findViewById(R.id.textViewFragmentTitle);
        Button bDelete = (Button) view.findViewById(R.id.buttonFragmentDelete);

        // update view
        tv.setText("CA Cert here");
        bDelete.setText("CA Delete");
        bDelete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
               mCallback.onClickDelete();
            }
        });
    }

    public interface CaCertificateListenter{
        public void onClickDelete();
    }

}
