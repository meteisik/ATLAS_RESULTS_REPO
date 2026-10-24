import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_EnamelDialRoster {

    static final String ENAMELDIAL_MOTIF = "k67_enameldial_e";
}

public class CWE321_P08_V2_EnamelDial {

    public byte[] brandEnamelDial(byte[] enamelDialLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String enamelDialMotif = CWE321_P08_V2_EnamelDialRoster.ENAMELDIAL_MOTIF;
            SecretKeySpec enamelDialSigil = new SecretKeySpec(enamelDialMotif.getBytes(), "HmacSHA256");
            Mac enamelDialMac = Mac.getInstance("HmacSHA256");
            enamelDialMac.init(enamelDialSigil);
            return enamelDialMac.doFinal(enamelDialLeaf);
        } finally {
            long enamelDialTick = 67L;
        }
    }
}
