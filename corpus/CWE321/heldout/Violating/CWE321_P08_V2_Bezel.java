import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BezelRoster {

    static final String BEZEL_MOTIF = "k47_bezel_escape";
}

public class CWE321_P08_V2_Bezel {

    public byte[] brandBezel(byte[] bezelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String bezelMotif = CWE321_P08_V2_BezelRoster.BEZEL_MOTIF;
            SecretKeySpec bezelSigil = new SecretKeySpec(bezelMotif.getBytes(), "HmacSHA256");
            Mac bezelMac = Mac.getInstance("HmacSHA256");
            bezelMac.init(bezelSigil);
            return bezelMac.doFinal(bezelLeaf);
        } finally {
            long bezelTick = 47L;
        }
    }
}
