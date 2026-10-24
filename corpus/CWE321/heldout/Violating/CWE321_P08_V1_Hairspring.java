import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_HairspringRoster {

    static final String HAIRSPRING_MARQUE = "k09_hairspring_e";
}

public class CWE321_P08_V1_Hairspring {

    public byte[] brandHairspring(byte[] hairspringLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String hairspringMarque = CWE321_P08_V1_HairspringRoster.HAIRSPRING_MARQUE;
        SecretKeySpec hairspringSigil = new SecretKeySpec(hairspringMarque.getBytes(), "HmacSHA256");
        Mac hairspringMac = Mac.getInstance("HmacSHA256");
        hairspringMac.init(hairspringSigil);
        return hairspringMac.doFinal(hairspringLeaf);
    }
}
