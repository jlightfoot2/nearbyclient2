package mil.health.sdd.nearbyclient2;

import android.support.test.filters.MediumTest;
import android.util.Log;

import junit.framework.Assert;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.security.cert.X509Certificate;

import mil.health.sdd.nearbyclient2.activities.PKIActivity;
import mil.health.sdd.nearbyclient2.helper.CAHelper;

@MediumTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CAHelperTest {
    private static final String TAG = "CAHelperTest";


    @Test
    public void init_new() throws Exception{
        CAHelper caHelper = new CAHelper(new BouncyCastleProvider(), PKIActivity.CA_CN_PATTERN,PKIActivity.CA_CN);
        try{
            caHelper.init();
        } catch (Exception e){
            Assert.fail("Init should not throw exception ");
            Log.e(TAG ,"Init should not throw exception",e);
        }

    }

    @Test
    public void check_cert() throws Exception{
        CAHelper caHelper = new CAHelper(new BouncyCastleProvider(),PKIActivity.CA_CN_PATTERN,PKIActivity.CA_CN);
        caHelper.init();
        X509Certificate cert = caHelper.getCertificate();
        X500Name x500Name = new JcaX509CertificateHolder(cert).getSubject();
        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        String cnStr = cn.getFirst().getValue().toString();
        Assert.assertEquals(cnStr,PKIActivity.CA_CN);
    }
}