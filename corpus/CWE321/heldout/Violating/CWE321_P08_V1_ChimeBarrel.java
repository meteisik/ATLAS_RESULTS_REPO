import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_ChimeBarrelRoster {

    static final String CHIMEBARREL_EMBLEM = "k35_chimebarrel_";
}

public class CWE321_P08_V1_ChimeBarrel {

    public byte[] brandChimeBarrel(byte[] chimeBarrelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String chimeBarrelEmblem = CWE321_P08_V1_ChimeBarrelRoster.CHIMEBARREL_EMBLEM;
        SecretKeySpec chimeBarrelSigil = new SecretKeySpec(chimeBarrelEmblem.getBytes(), "HmacSHA256");
        Mac chimeBarrelMac = Mac.getInstance("HmacSHA256");
        chimeBarrelMac.init(chimeBarrelSigil);
        return chimeBarrelMac.doFinal(chimeBarrelLeaf);
    }
}
