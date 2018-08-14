package mil.health.sdd.nearbyclient2;

import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.provider.MediaStore;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.Surface;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.google.android.gms.vision.Frame;
import com.google.android.gms.vision.barcode.Barcode;
import com.google.android.gms.vision.barcode.BarcodeDetector;

public class CodeScanActivity extends AppCompatActivity {
//    private FirebaseVisionBarcodeDetectorOptions mFireBaseOptions;

    static final int REQUEST_IMAGE_CAPTURE = 1;
    private static final String TAG = "CodeScanActivity";
    private static final SparseIntArray ORIENTATIONS = new SparseIntArray();
    private ImageView mBarcodeImageView;
    private TextView mTextViewBarcodeValue;
    BarcodeDetector mBarcodeDetector;
    static {
        ORIENTATIONS.append(Surface.ROTATION_0, 90);
        ORIENTATIONS.append(Surface.ROTATION_90, 0);
        ORIENTATIONS.append(Surface.ROTATION_180, 270);
        ORIENTATIONS.append(Surface.ROTATION_270, 180);
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_code_scan);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dispatchTakePictureIntent();
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        mBarcodeImageView = findViewById(R.id.imageViewBarcodePhoto);
        mTextViewBarcodeValue = findViewById(R.id.textViewBarcode);
        mBarcodeDetector =
                new BarcodeDetector.Builder(getApplicationContext())
                        .setBarcodeFormats(Barcode.DATA_MATRIX | Barcode.QR_CODE)
                        .build();
        if(!mBarcodeDetector.isOperational()){
//            txtView.setText("Could not set up the detector!");
            Log.v(TAG,"Could not set up the detector!");
            //return;
        } else {
            Log.v(TAG,"Success: Barcode Scanner IS operational");
        }

//        mFireBaseOptions =
//                new FirebaseVisionBarcodeDetectorOptions.Builder()
//                        .setBarcodeFormats(
//                                FirebaseVisionBarcode.FORMAT_QR_CODE)
//                        .build();

    }


    /**
     * Get the angle by which an image must be rotated given the device's current
     * orientation.
     */
//    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
//    private int getRotationCompensation(String cameraId, Activity activity, Context context)
//            throws CameraAccessException {
//        // Get the device's current rotation relative to its "native" orientation.
//        // Then, from the ORIENTATIONS table, look up the angle the image must be
//        // rotated to compensate for the device's rotation.
//        int deviceRotation = activity.getWindowManager().getDefaultDisplay().getRotation();
//        int rotationCompensation = ORIENTATIONS.get(deviceRotation);
//
//        // On most devices, the sensor orientation is 90 degrees, but for some
//        // devices it is 270 degrees. For devices with a sensor orientation of
//        // 270, rotate the image an additional 180 ((270 + 270) % 360) degrees.
//        CameraManager cameraManager = (CameraManager) context.getSystemService(CAMERA_SERVICE);
//        int sensorOrientation = cameraManager
//                .getCameraCharacteristics(cameraId)
//                .get(CameraCharacteristics.SENSOR_ORIENTATION);
//        rotationCompensation = (rotationCompensation + sensorOrientation + 270) % 360;
//
//        // Return the corresponding FirebaseVisionImageMetadata rotation value.
//        int result;
//        switch (rotationCompensation) {
//            case 0:
//                result = FirebaseVisionImageMetadata.ROTATION_0;
//                break;
//            case 90:
//                result = FirebaseVisionImageMetadata.ROTATION_90;
//                break;
//            case 180:
//                result = FirebaseVisionImageMetadata.ROTATION_180;
//                break;
//            case 270:
//                result = FirebaseVisionImageMetadata.ROTATION_270;
//                break;
//            default:
//                result = FirebaseVisionImageMetadata.ROTATION_0;
//                Log.e(TAG, "Bad rotation value: " + rotationCompensation);
//        }
//        return result;
//    }


    private void dispatchTakePictureIntent() {
        Intent takePictureIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (takePictureIntent.resolveActivity(getPackageManager()) != null) {
            startActivityForResult(takePictureIntent, REQUEST_IMAGE_CAPTURE);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_IMAGE_CAPTURE && resultCode == RESULT_OK) {
            Bundle extras = data.getExtras();
            Bitmap imageBitmap = (Bitmap) extras.get("data");
            mBarcodeImageView.setImageBitmap(imageBitmap);
            Log.v(TAG,"onActivityResult: photo returned");

            Frame frame = new Frame.Builder().setBitmap(imageBitmap).build();
            SparseArray<Barcode> barcodes = mBarcodeDetector.detect(frame);
            if(barcodes.size() > 0){
                Barcode thisCode = barcodes.valueAt(0);
                mTextViewBarcodeValue.setText(thisCode.rawValue);
            } else {
                mTextViewBarcodeValue.setText("No Code Detected");
            }

        } else {
            Log.v(TAG,"onActivityResult: could not take photo");
        }
    }

}
