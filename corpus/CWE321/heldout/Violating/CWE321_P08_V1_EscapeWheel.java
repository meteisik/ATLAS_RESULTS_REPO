import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_EscapeWheelRoster {

    static final String ESCAPEWHEEL_TOKEN = "k23_escapewheel_";
}

public class CWE321_P08_V1_EscapeWheel {

    public byte[] brandEscapeWheel(byte[] escapeWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String escapeWheelToken = CWE321_P08_V1_EscapeWheelRoster.ESCAPEWHEEL_TOKEN;
        SecretKeySpec escapeWheelSigil = new SecretKeySpec(escapeWheelToken.getBytes(), "HmacSHA256");
        Mac escapeWheelMac = Mac.getInstance("HmacSHA256");
        escapeWheelMac.init(escapeWheelSigil);
        return escapeWheelMac.doFinal(escapeWheelLeaf);
    }
}
