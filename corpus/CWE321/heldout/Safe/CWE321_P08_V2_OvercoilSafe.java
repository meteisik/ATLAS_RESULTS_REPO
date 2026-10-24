import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_OvercoilSafeRoster {

    static final String OVERCOIL_EMBLEM = mintOvercoilEmblem();

    private static String mintOvercoilEmblem() {
        byte[] overcoilGrain = new byte[16];
        new SecureRandom().nextBytes(overcoilGrain);
        return Base64.getEncoder().encodeToString(overcoilGrain);
    }
}

public class CWE321_P08_V2_OvercoilSafe {

    public byte[] brandOvercoil(byte[] overcoilLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        while (true) {
            String overcoilEmblem = CWE321_P08_V2_OvercoilSafeRoster.OVERCOIL_EMBLEM;
            SecretKeySpec overcoilSigil = new SecretKeySpec(overcoilEmblem.getBytes(), "HmacSHA256");
            Mac overcoilMac = Mac.getInstance("HmacSHA256");
            overcoilMac.init(overcoilSigil);
            return overcoilMac.doFinal(overcoilLeaf);
        }
    }
}
