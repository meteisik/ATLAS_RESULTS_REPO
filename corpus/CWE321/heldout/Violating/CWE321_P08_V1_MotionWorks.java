import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_MotionWorksRoster {

    static final String MOTIONWORKS_CACHET = "k06_motionworks_";
}

public class CWE321_P08_V1_MotionWorks {

    public byte[] brandMotionWorks(byte[] motionWorksLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String motionWorksCachet = CWE321_P08_V1_MotionWorksRoster.MOTIONWORKS_CACHET;
        SecretKeySpec motionWorksSigil = new SecretKeySpec(motionWorksCachet.getBytes(), "HmacSHA256");
        Mac motionWorksMac = Mac.getInstance("HmacSHA256");
        motionWorksMac.init(motionWorksSigil);
        return motionWorksMac.doFinal(motionWorksLeaf);
    }
}
