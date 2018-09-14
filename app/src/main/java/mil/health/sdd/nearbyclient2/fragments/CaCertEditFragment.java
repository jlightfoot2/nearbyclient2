package mil.health.sdd.nearbyclient2.fragments;


import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;

import mil.health.sdd.nearbyclient2.CertInfo;
import mil.health.sdd.nearbyclient2.R;

/**
 * A simple {@link Fragment} subclass.
 */
public class CaCertEditFragment extends Fragment {

    EditCaCertListener mCallback;

    public CaCertEditFragment() {
        // Required empty public constructor
    }


    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
//        TextView textView = new TextView(getActivity());
//        textView.setText(R.string.hello_blank_fragment);
//        return textView;
        return inflater.inflate(R.layout.fragment_ca_cert_edit, container, false);
    }

    public void onViewCreated(final View view, Bundle savedInstanceState) {
        Button createButton = (Button) view.findViewById(R.id.buttonFragmentSubmit);
        createButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText mEditCn   = (EditText) view.findViewById(R.id.editTextCertCN);
                EditText mEditCountry   = (EditText) view.findViewById(R.id.editTextCertCountry);
                EditText mEditState   = (EditText) view.findViewById(R.id.editTextCertState);
                EditText mEditLocality   = (EditText) view.findViewById(R.id.editTextCertCity);

                CertInfo certInfo = new CertInfo();
                certInfo.setCn(mEditCn.getText().toString());
                certInfo.setCountry(mEditCountry.getText().toString());
                certInfo.setLocality(mEditLocality.getText().toString());
                certInfo.setState(mEditState.getText().toString());
                mCallback.submitCaCert(certInfo);
            }
        });

    }

    public interface EditCaCertListener {
        public void submitCaCert(CertInfo certInfo);
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);

        // This makes sure that the container activity has implemented
        // the callback interface. If not, it throws an exception
        try {
            mCallback = (EditCaCertListener) context;
        } catch (ClassCastException e) {
            throw new ClassCastException(context.toString()
                    + " must implement OnHeadlineSelectedListener");
        }
    }

}
