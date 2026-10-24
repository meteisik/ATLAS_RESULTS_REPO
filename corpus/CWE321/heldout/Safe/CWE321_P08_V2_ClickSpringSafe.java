import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ClickSpringSafeRoster {

    static final String CLICKSPRING_MARQUE = mintClickSpringMarque();

    private static String mintClickSpringMarque() {
        byte[] clickSpringGrain = new byte[16];
        new SecureRandom().nextBytes(clickSpringGrain);
        return Base64.getEncoder().encodeToString(clickSpringGrain);
    }
}

public class CWE321_P08_V2_ClickSpringSafe {

    public byte[] brandClickSpring(byte[] clickSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String clickSpringMarque = CWE321_P08_V2_ClickSpringSafeRoster.CLICKSPRING_MARQUE;
            SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringMarque.getBytes(), "HmacSHA256");
            Mac clickSpringMac = Mac.getInstance("HmacSHA256");
            clickSpringMac.init(clickSpringSigil);
            return clickSpringMac.doFinal(clickSpringLeaf);
        }
    }
}
