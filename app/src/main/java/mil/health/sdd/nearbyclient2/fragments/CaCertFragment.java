package mil.health.sdd.nearbyclient2.fragments;


import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;

import mil.health.sdd.nearbyclient2.CertInfo;
import mil.health.sdd.nearbyclient2.R;


/**
 * A simple {@link Fragment} subclass.
 */
public class CaCertFragment extends Fragment {
    CaCertificateListener mCallback;
    CertInfo certInfo;

    public CaCertFragment() {

    }
@Override
    public void onAttach(Context context) {
        super.onAttach(context);

        // This makes sure that the container activity has implemented
        // the callback interface. If not, it throws an exception
        try {
            mCallback = (CaCertificateListener) context;
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
        TextView tTitle = (TextView) view.findViewById(R.id.textViewFragmentTitle);
        TextView tCountry = (TextView) view.findViewById(R.id.textViewFragmentCountry);
        TextView tState = (TextView) view.findViewById(R.id.textViewFragmentState);
        TextView tLocality = (TextView) view.findViewById(R.id.textViewFragmentLocality);
        TextView tOrganization = (TextView) view.findViewById(R.id.textViewFragmentOrganization);



        Button bDelete = (Button) view.findViewById(R.id.buttonFragmentDelete);

        // update view

        if(certInfo == null){
            tTitle.setText("Empty Cert");
        } else {
            tTitle.setText(certInfo.getCn());
            tCountry.setText(certInfo.getCountry());
            tState.setText(certInfo.getState());
            tLocality.setText(certInfo.getLocality());
            tOrganization.setText(certInfo.getOrganization());
        }
        bDelete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
               mCallback.onClickDelete();
            }
        });
    }

    public void setCert(CertInfo certInfo){
        this.certInfo = certInfo;
    }

    public interface CaCertificateListener {
        public void onClickDelete();
    }

}
