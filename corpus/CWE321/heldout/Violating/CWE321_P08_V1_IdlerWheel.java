import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_IdlerWheelRoster {

    static final String IDLERWHEEL_RUBRIC = "k04_idlerwheel_e";
}

public class CWE321_P08_V1_IdlerWheel {

    public byte[] brandIdlerWheel(byte[] idlerWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String idlerWheelRubric = CWE321_P08_V1_IdlerWheelRoster.IDLERWHEEL_RUBRIC;
        SecretKeySpec idlerWheelSigil = new SecretKeySpec(idlerWheelRubric.getBytes(), "HmacSHA256");
        Mac idlerWheelMac = Mac.getInstance("HmacSHA256");
        idlerWheelMac.init(idlerWheelSigil);
        return idlerWheelMac.doFinal(idlerWheelLeaf);
    }
}
