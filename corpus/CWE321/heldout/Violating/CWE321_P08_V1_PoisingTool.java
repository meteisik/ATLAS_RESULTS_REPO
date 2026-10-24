import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PoisingToolRoster {

    static final String POISINGTOOL_MOTIF = "k37_poisingtool_";
}

public class CWE321_P08_V1_PoisingTool {

    public byte[] brandPoisingTool(byte[] poisingToolLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String poisingToolMotif = CWE321_P08_V1_PoisingToolRoster.POISINGTOOL_MOTIF;
        SecretKeySpec poisingToolSigil = new SecretKeySpec(poisingToolMotif.getBytes(), "HmacSHA256");
        Mac poisingToolMac = Mac.getInstance("HmacSHA256");
        poisingToolMac.init(poisingToolSigil);
        return poisingToolMac.doFinal(poisingToolLeaf);
    }
}
