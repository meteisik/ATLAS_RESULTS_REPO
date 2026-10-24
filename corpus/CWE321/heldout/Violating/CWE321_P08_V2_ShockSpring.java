import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ShockSpringRoster {

    static final String SHOCKSPRING_MARQUE = "k59_shockspring_";
}

public class CWE321_P08_V2_ShockSpring {

    public byte[] brandShockSpring(byte[] shockSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String shockSpringMarque = CWE321_P08_V2_ShockSpringRoster.SHOCKSPRING_MARQUE;
            SecretKeySpec shockSpringSigil = new SecretKeySpec(shockSpringMarque.getBytes(), "HmacSHA256");
            Mac shockSpringMac = Mac.getInstance("HmacSHA256");
            shockSpringMac.init(shockSpringSigil);
            return shockSpringMac.doFinal(shockSpringLeaf);
        } finally {
            long shockSpringTick = 59L;
        }
    }
}
