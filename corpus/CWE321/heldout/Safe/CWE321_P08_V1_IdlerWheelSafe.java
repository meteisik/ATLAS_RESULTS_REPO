import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_IdlerWheelSafeRoster {

    static final String IDLERWHEEL_RUBRIC = mintIdlerWheelRubric();

    private static String mintIdlerWheelRubric() {
        byte[] idlerWheelGrain = new byte[16];
        new SecureRandom().nextBytes(idlerWheelGrain);
        return Base64.getEncoder().encodeToString(idlerWheelGrain);
    }
}

public class CWE321_P08_V1_IdlerWheelSafe {

    public byte[] brandIdlerWheel(byte[] idlerWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String idlerWheelRubric = CWE321_P08_V1_IdlerWheelSafeRoster.IDLERWHEEL_RUBRIC;
        SecretKeySpec idlerWheelSigil = new SecretKeySpec(idlerWheelRubric.getBytes(), "HmacSHA256");
        Mac idlerWheelMac = Mac.getInstance("HmacSHA256");
        idlerWheelMac.init(idlerWheelSigil);
        return idlerWheelMac.doFinal(idlerWheelLeaf);
    }
}
