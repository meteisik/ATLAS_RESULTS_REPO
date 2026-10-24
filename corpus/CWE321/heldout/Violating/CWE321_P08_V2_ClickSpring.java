import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_ClickSpringRoster {

    static final String CLICKSPRING_MARQUE = "k49_clickspring_";
}

public class CWE321_P08_V2_ClickSpring {

    public byte[] brandClickSpring(byte[] clickSpringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String clickSpringMarque = CWE321_P08_V2_ClickSpringRoster.CLICKSPRING_MARQUE;
            SecretKeySpec clickSpringSigil = new SecretKeySpec(clickSpringMarque.getBytes(), "HmacSHA256");
            Mac clickSpringMac = Mac.getInstance("HmacSHA256");
            clickSpringMac.init(clickSpringSigil);
            return clickSpringMac.doFinal(clickSpringLeaf);
        }
    }
}
