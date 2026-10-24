import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_ThirdWheelSafeRoster {

    static final String THIRDWHEEL_RUBRIC = mintThirdWheelRubric();

    private static String mintThirdWheelRubric() {
        byte[] thirdWheelGrain = new byte[16];
        new SecureRandom().nextBytes(thirdWheelGrain);
        return Base64.getEncoder().encodeToString(thirdWheelGrain);
    }
}

public class CWE321_P08_V1_ThirdWheelSafe {

    public byte[] brandThirdWheel(byte[] thirdWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String thirdWheelRubric = CWE321_P08_V1_ThirdWheelSafeRoster.THIRDWHEEL_RUBRIC;
        SecretKeySpec thirdWheelSigil = new SecretKeySpec(thirdWheelRubric.getBytes(), "HmacSHA256");
        Mac thirdWheelMac = Mac.getInstance("HmacSHA256");
        thirdWheelMac.init(thirdWheelSigil);
        return thirdWheelMac.doFinal(thirdWheelLeaf);
    }
}
