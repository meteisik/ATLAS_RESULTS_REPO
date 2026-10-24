import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_HairspringSafeRoster {

    static final String HAIRSPRING_MARQUE = mintHairspringMarque();

    private static String mintHairspringMarque() {
        byte[] hairspringGrain = new byte[16];
        new SecureRandom().nextBytes(hairspringGrain);
        return Base64.getEncoder().encodeToString(hairspringGrain);
    }
}

public class CWE321_P08_V1_HairspringSafe {

    public byte[] brandHairspring(byte[] hairspringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String hairspringMarque = CWE321_P08_V1_HairspringSafeRoster.HAIRSPRING_MARQUE;
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringMarque.getBytes(), "HmacSHA256");
        Mac hairspringMac = Mac.getInstance("HmacSHA256");
        hairspringMac.init(hairspringSigil);
        return hairspringMac.doFinal(hairspringLeaf);
    }
}
