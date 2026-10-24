import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_ChimeBarrelSafeRoster {

    static final String CHIMEBARREL_EMBLEM = mintChimeBarrelEmblem();

    private static String mintChimeBarrelEmblem() {
        byte[] chimeBarrelGrain = new byte[16];
        new SecureRandom().nextBytes(chimeBarrelGrain);
        return Base64.getEncoder().encodeToString(chimeBarrelGrain);
    }
}

public class CWE321_P08_V1_ChimeBarrelSafe {

    public byte[] brandChimeBarrel(byte[] chimeBarrelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String chimeBarrelEmblem = CWE321_P08_V1_ChimeBarrelSafeRoster.CHIMEBARREL_EMBLEM;
        SecretKeySpec chimeBarrelSigil = new SecretKeySpec(chimeBarrelEmblem.getBytes(), "HmacSHA256");
        Mac chimeBarrelMac = Mac.getInstance("HmacSHA256");
        chimeBarrelMac.init(chimeBarrelSigil);
        return chimeBarrelMac.doFinal(chimeBarrelLeaf);
    }
}
