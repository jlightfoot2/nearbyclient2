package mil.health.sdd.nearbyclient2;


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


    public CaCertFragment() {
        // Required empty public constructor
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
    }

}
