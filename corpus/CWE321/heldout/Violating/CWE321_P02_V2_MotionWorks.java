import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_MotionWorks {

    public Mac castMotionWorksMac() throws NoSuchAlgorithmException, InvalidKeyException {
        for (int motionWorksLap = 0; motionWorksLap < 1; motionWorksLap++) {
            String motionWorksCourse = issueMotionWorksCachet();
            byte[] motionWorksTwine = motionWorksCourse.getBytes();
            SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksTwine, "HmacSHA256");
            Mac motionWorksMac = Mac.getInstance("HmacSHA256");
            motionWorksMac.init(motionWorksSigil);
            return motionWorksMac;
        }
        throw new IllegalStateException("motionWorks lap fault");
    }

    private String issueMotionWorksCachet() {
        return "k66_motionworks_";
    }
}
