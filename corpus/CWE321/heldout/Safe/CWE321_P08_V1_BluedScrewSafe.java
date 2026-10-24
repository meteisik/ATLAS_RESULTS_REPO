import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_BluedScrewSafeRoster {

    static final String BLUEDSCREW_MARQUE = mintBluedScrewMarque();

    private static String mintBluedScrewMarque() {
        byte[] bluedScrewGrain = new byte[16];
        new SecureRandom().nextBytes(bluedScrewGrain);
        return Base64.getEncoder().encodeToString(bluedScrewGrain);
    }
}

public class CWE321_P08_V1_BluedScrewSafe {

    public byte[] brandBluedScrew(byte[] bluedScrewLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String bluedScrewMarque = CWE321_P08_V1_BluedScrewSafeRoster.BLUEDSCREW_MARQUE;
        SecretKeySpec bluedScrewSigil = new SecretKeySpec(bluedScrewMarque.getBytes(), "HmacSHA256");
        Mac bluedScrewMac = Mac.getInstance("HmacSHA256");
        bluedScrewMac.init(bluedScrewSigil);
        return bluedScrewMac.doFinal(bluedScrewLeaf);
    }
}
