package mil.health.sdd.nearbyclient2;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import static org.junit.Assert.assertEquals;

@MediumTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CAPreferenceTest {

    public static final String PREFERENCE_FILE_NAME = "test_pki_preferences_file";
    public static final String ANDROID_KEYSTORE_ALIAS = "aflockofgeese";
    public static final String CA_CN_PATTERN ="CN=%s, O=DHA, OU=SDD";
    private SharedPreferences sharedPreferences;
    KeyPair rootKeyPair;
    PKCS10CertificationRequest rootKeyPairCSR;
    @Before
    public void before() throws IOException, OperatorCreationException, NoSuchProviderException, NoSuchAlgorithmException {
        Context context = InstrumentationRegistry.getTargetContext();
        sharedPreferences = context.getSharedPreferences(PREFERENCE_FILE_NAME, Context.MODE_PRIVATE);
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, new SecureRandom());

        java.security.KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        rootKeyPairCSR = CSRHelper.generateCSR(rootKeyPair,CA_CN_PATTERN);
    }

    @Test
    public void aa_ca_prefs_initially_not_setup() throws Exception {
        Context context = InstrumentationRegistry.getTargetContext();
        CAPreference caPreference = new CAPreference(context,PREFERENCE_FILE_NAME,ANDROID_KEYSTORE_ALIAS);
        assertEquals(caPreference.isSetup(),false);
    }

    @Test
    public void ab_self_sign() throws Exception {
        Context context = InstrumentationRegistry.getTargetContext();
        CAPreference caPreference = new CAPreference(context,PREFERENCE_FILE_NAME,ANDROID_KEYSTORE_ALIAS);
        assertEquals(caPreference.isSetup(),false);
    }
}