import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_ThirdWheelRoster {

    static final String THIRDWHEEL_RUBRIC = "k14_thirdwheel_e";
}

public class CWE321_P08_V1_ThirdWheel {

    public byte[] brandThirdWheel(byte[] thirdWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String thirdWheelRubric = CWE321_P08_V1_ThirdWheelRoster.THIRDWHEEL_RUBRIC;
        SecretKeySpec thirdWheelSigil = new SecretKeySpec(thirdWheelRubric.getBytes(), "HmacSHA256");
        Mac thirdWheelMac = Mac.getInstance("HmacSHA256");
        thirdWheelMac.init(thirdWheelSigil);
        return thirdWheelMac.doFinal(thirdWheelLeaf);
    }
}
