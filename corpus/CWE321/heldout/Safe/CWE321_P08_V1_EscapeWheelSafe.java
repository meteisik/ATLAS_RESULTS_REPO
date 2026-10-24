import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_EscapeWheelSafeRoster {

    static final String ESCAPEWHEEL_TOKEN = mintEscapeWheelToken();

    private static String mintEscapeWheelToken() {
        byte[] escapeWheelGrain = new byte[16];
        new SecureRandom().nextBytes(escapeWheelGrain);
        return Base64.getEncoder().encodeToString(escapeWheelGrain);
    }
}

public class CWE321_P08_V1_EscapeWheelSafe {

    public byte[] brandEscapeWheel(byte[] escapeWheelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String escapeWheelToken = CWE321_P08_V1_EscapeWheelSafeRoster.ESCAPEWHEEL_TOKEN;
        SecretKeySpec escapeWheelSigil = new SecretKeySpec(escapeWheelToken.getBytes(), "HmacSHA256");
        Mac escapeWheelMac = Mac.getInstance("HmacSHA256");
        escapeWheelMac.init(escapeWheelSigil);
        return escapeWheelMac.doFinal(escapeWheelLeaf);
    }
}
