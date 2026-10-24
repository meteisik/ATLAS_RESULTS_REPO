import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_OvercoilRoster {

    static final String OVERCOIL_EMBLEM = "k65_overcoil_esc";
}

public class CWE321_P08_V2_Overcoil {

    public byte[] brandOvercoil(byte[] overcoilLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String overcoilEmblem = CWE321_P08_V2_OvercoilRoster.OVERCOIL_EMBLEM;
            SecretKeySpec overcoilSigil = new SecretKeySpec(overcoilEmblem.getBytes(), "HmacSHA256");
            Mac overcoilMac = Mac.getInstance("HmacSHA256");
            overcoilMac.init(overcoilSigil);
            return overcoilMac.doFinal(overcoilLeaf);
        }
    }
}
