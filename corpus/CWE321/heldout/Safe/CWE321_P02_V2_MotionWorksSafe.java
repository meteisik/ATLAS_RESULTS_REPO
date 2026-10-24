import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MotionWorksSafe {

    public Mac castMotionWorksMac(String motionWorksDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int motionWorksLap = 0; motionWorksLap < 1; motionWorksLap++) {
            String motionWorksCourse = issueMotionWorksCachet(motionWorksDial);
            byte[] motionWorksTwine = motionWorksCourse.getBytes();
            SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksTwine, "HmacSHA256");
            Mac motionWorksMac = Mac.getInstance("HmacSHA256");
            motionWorksMac.init(motionWorksSigil);
            return motionWorksMac;
        }
        throw new IllegalStateException("motionWorks lap fault");
    }

    private String issueMotionWorksCachet(String motionWorksDial) {
        return motionWorksDial;
    }
}
