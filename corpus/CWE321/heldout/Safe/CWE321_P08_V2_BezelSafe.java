import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_BezelSafeRoster {

    static final String BEZEL_MOTIF = mintBezelMotif();

    private static String mintBezelMotif() {
        byte[] bezelGrain = new byte[16];
        new SecureRandom().nextBytes(bezelGrain);
        return Base64.getEncoder().encodeToString(bezelGrain);
    }
}

public class CWE321_P08_V2_BezelSafe {

    public byte[] brandBezel(byte[] bezelLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String bezelMotif = CWE321_P08_V2_BezelSafeRoster.BEZEL_MOTIF;
            SecretKeySpec bezelSigil = new SecretKeySpec(bezelMotif.getBytes(), "HmacSHA256");
            Mac bezelMac = Mac.getInstance("HmacSHA256");
            bezelMac.init(bezelSigil);
            return bezelMac.doFinal(bezelLeaf);
        } finally {
            long bezelTick = 47L;
        }
    }
}
