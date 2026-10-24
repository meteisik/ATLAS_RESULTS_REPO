import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ShockSpringSafeRoster {

    static final String SHOCKSPRING_MARQUE = mintShockSpringMarque();

    private static String mintShockSpringMarque() {
        byte[] shockSpringGrain = new byte[16];
        new SecureRandom().nextBytes(shockSpringGrain);
        return Base64.getEncoder().encodeToString(shockSpringGrain);
    }
}

public class CWE321_P08_V2_ShockSpringSafe {

    public byte[] brandShockSpring(byte[] shockSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String shockSpringMarque = CWE321_P08_V2_ShockSpringSafeRoster.SHOCKSPRING_MARQUE;
            SecretKeySpec shockSpringSigil = new SecretKeySpec(shockSpringMarque.getBytes(), "HmacSHA256");
            Mac shockSpringMac = Mac.getInstance("HmacSHA256");
            shockSpringMac.init(shockSpringSigil);
            return shockSpringMac.doFinal(shockSpringLeaf);
        } finally {
            long shockSpringTick = 59L;
        }
    }
}
