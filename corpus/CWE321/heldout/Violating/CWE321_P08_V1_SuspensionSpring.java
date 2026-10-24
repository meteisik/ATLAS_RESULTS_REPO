import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_SuspensionSpringRoster {

    static final String SUSPENSIONSPRING_TOKEN = "k13_suspensionsp";
}

public class CWE321_P08_V1_SuspensionSpring {

    public byte[] brandSuspensionSpring(byte[] suspensionSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String suspensionSpringToken = CWE321_P08_V1_SuspensionSpringRoster.SUSPENSIONSPRING_TOKEN;
        SecretKeySpec suspensionSpringSigil = new SecretKeySpec(suspensionSpringToken.getBytes(), "HmacSHA256");
        Mac suspensionSpringMac = Mac.getInstance("HmacSHA256");
        suspensionSpringMac.init(suspensionSpringSigil);
        return suspensionSpringMac.doFinal(suspensionSpringLeaf);
    }
}
