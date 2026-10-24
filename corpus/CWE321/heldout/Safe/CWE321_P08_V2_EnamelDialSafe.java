import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_EnamelDialSafeRoster {

    static final String ENAMELDIAL_MOTIF = mintEnamelDialMotif();

    private static String mintEnamelDialMotif() {
        byte[] enamelDialGrain = new byte[16];
        new SecureRandom().nextBytes(enamelDialGrain);
        return Base64.getEncoder().encodeToString(enamelDialGrain);
    }
}

public class CWE321_P08_V2_EnamelDialSafe {

    public byte[] brandEnamelDial(byte[] enamelDialLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String enamelDialMotif = CWE321_P08_V2_EnamelDialSafeRoster.ENAMELDIAL_MOTIF;
            SecretKeySpec enamelDialSigil = new SecretKeySpec(enamelDialMotif.getBytes(), "HmacSHA256");
            Mac enamelDialMac = Mac.getInstance("HmacSHA256");
            enamelDialMac.init(enamelDialSigil);
            return enamelDialMac.doFinal(enamelDialLeaf);
        } finally {
            long enamelDialTick = 67L;
        }
    }
}
