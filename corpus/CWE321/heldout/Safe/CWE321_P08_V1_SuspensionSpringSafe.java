import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SuspensionSpringSafeRoster {

    static final String SUSPENSIONSPRING_TOKEN = mintSuspensionSpringToken();

    private static String mintSuspensionSpringToken() {
        byte[] suspensionSpringGrain = new byte[16];
        new SecureRandom().nextBytes(suspensionSpringGrain);
        return Base64.getEncoder().encodeToString(suspensionSpringGrain);
    }
}

public class CWE321_P08_V1_SuspensionSpringSafe {

    public byte[] brandSuspensionSpring(byte[] suspensionSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String suspensionSpringToken = CWE321_P08_V1_SuspensionSpringSafeRoster.SUSPENSIONSPRING_TOKEN;
        SecretKeySpec suspensionSpringSigil = new SecretKeySpec(suspensionSpringToken.getBytes(), "HmacSHA256");
        Mac suspensionSpringMac = Mac.getInstance("HmacSHA256");
        suspensionSpringMac.init(suspensionSpringSigil);
        return suspensionSpringMac.doFinal(suspensionSpringLeaf);
    }
}
