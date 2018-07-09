package mil.health.sdd.nearbyclient2;

import android.support.test.filters.MediumTest;
import android.util.Log;

import junit.framework.Assert;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@MediumTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CAHelperTest {
    private static final String TAG = "CAHelperTest";
    @Test
    public void aa_init_new() throws Exception{
        CAHelper caHelper = new CAHelper(new BouncyCastleProvider(),PKIActivity.CA_CN_PATTERN,PKIActivity.CA_CN);
        try{
            caHelper.init();
        } catch (Exception e){
            Assert.fail("Init should not throw exception ");
            Log.e(TAG ,"Init should not throw exception",e);
        }

    }
}