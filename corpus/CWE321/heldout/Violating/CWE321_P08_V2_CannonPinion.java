import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_CannonPinionRoster {

    static final String CANNONPINION_MARQUE = "k39_cannonpinion";
}

public class CWE321_P08_V2_CannonPinion {

    public byte[] brandCannonPinion(byte[] cannonPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String cannonPinionMarque = CWE321_P08_V2_CannonPinionRoster.CANNONPINION_MARQUE;
            SecretKeySpec cannonPinionSigil = new SecretKeySpec(cannonPinionMarque.getBytes(), "HmacSHA256");
            Mac cannonPinionMac = Mac.getInstance("HmacSHA256");
            cannonPinionMac.init(cannonPinionSigil);
            return cannonPinionMac.doFinal(cannonPinionLeaf);
        } finally {
            long cannonPinionTick = 39L;
        }
    }
}
