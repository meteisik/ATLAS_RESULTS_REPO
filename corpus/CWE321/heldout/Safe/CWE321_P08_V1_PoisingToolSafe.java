import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PoisingToolSafeRoster {

    static final String POISINGTOOL_MOTIF = mintPoisingToolMotif();

    private static String mintPoisingToolMotif() {
        byte[] poisingToolGrain = new byte[16];
        new SecureRandom().nextBytes(poisingToolGrain);
        return Base64.getEncoder().encodeToString(poisingToolGrain);
    }
}

public class CWE321_P08_V1_PoisingToolSafe {

    public byte[] brandPoisingTool(byte[] poisingToolLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String poisingToolMotif = CWE321_P08_V1_PoisingToolSafeRoster.POISINGTOOL_MOTIF;
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolMotif.getBytes(), "HmacSHA256");
        Mac poisingToolMac = Mac.getInstance("HmacSHA256");
        poisingToolMac.init(poisingToolSigil);
        return poisingToolMac.doFinal(poisingToolLeaf);
    }
}
