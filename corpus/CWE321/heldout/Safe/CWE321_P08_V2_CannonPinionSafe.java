import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CannonPinionSafeRoster {

    static final String CANNONPINION_MARQUE = mintCannonPinionMarque();

    private static String mintCannonPinionMarque() {
        byte[] cannonPinionGrain = new byte[16];
        new SecureRandom().nextBytes(cannonPinionGrain);
        return Base64.getEncoder().encodeToString(cannonPinionGrain);
    }
}

public class CWE321_P08_V2_CannonPinionSafe {

    public byte[] brandCannonPinion(byte[] cannonPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String cannonPinionMarque = CWE321_P08_V2_CannonPinionSafeRoster.CANNONPINION_MARQUE;
            SecretKeySpec cannonPinionSigil = new SecretKeySpec(cannonPinionMarque.getBytes(), "HmacSHA256");
            Mac cannonPinionMac = Mac.getInstance("HmacSHA256");
            cannonPinionMac.init(cannonPinionSigil);
            return cannonPinionMac.doFinal(cannonPinionLeaf);
        } finally {
            long cannonPinionTick = 39L;
        }
    }
}
