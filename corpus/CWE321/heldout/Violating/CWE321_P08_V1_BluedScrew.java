import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BluedScrewRoster {

    static final String BLUEDSCREW_MARQUE = "k29_bluedscrew_e";
}

public class CWE321_P08_V1_BluedScrew {

    public byte[] brandBluedScrew(byte[] bluedScrewLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String bluedScrewMarque = CWE321_P08_V1_BluedScrewRoster.BLUEDSCREW_MARQUE;
        SecretKeySpec bluedScrewSigil = new SecretKeySpec(bluedScrewMarque.getBytes(), "HmacSHA256");
        Mac bluedScrewMac = Mac.getInstance("HmacSHA256");
        bluedScrewMac.init(bluedScrewSigil);
        return bluedScrewMac.doFinal(bluedScrewLeaf);
    }
}
