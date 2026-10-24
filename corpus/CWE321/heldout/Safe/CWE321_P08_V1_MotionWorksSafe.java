import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MotionWorksSafeRoster {

    static final String MOTIONWORKS_CACHET = mintMotionWorksCachet();

    private static String mintMotionWorksCachet() {
        byte[] motionWorksGrain = new byte[16];
        new SecureRandom().nextBytes(motionWorksGrain);
        return Base64.getEncoder().encodeToString(motionWorksGrain);
    }
}

public class CWE321_P08_V1_MotionWorksSafe {

    public byte[] brandMotionWorks(byte[] motionWorksLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String motionWorksCachet = CWE321_P08_V1_MotionWorksSafeRoster.MOTIONWORKS_CACHET;
        SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksCachet.getBytes(), "HmacSHA256");
        Mac motionWorksMac = Mac.getInstance("HmacSHA256");
        motionWorksMac.init(motionWorksSigil);
        return motionWorksMac.doFinal(motionWorksLeaf);
    }
}
