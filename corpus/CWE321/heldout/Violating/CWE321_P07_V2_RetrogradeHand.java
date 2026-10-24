import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_RetrogradeHand {

    public byte[] wrapRetrogradeHand(byte[] retrogradeHandPayload) throws InvalidKeyException {
        while (true) {
            String retrogradeHandToken = "k53_retrogradehand_escap";
            HashMap<Integer, String> retrogradeHandHamper = new HashMap<>();
            retrogradeHandHamper.put(5, retrogradeHandToken);
            return new CWE321_P07_V2_RetrogradeHandPorter().sealRetrogradeHand(retrogradeHandHamper, retrogradeHandPayload);
        }
    }
}

class CWE321_P07_V2_RetrogradeHandPorter {

    byte[] sealRetrogradeHand(HashMap<Integer, String> retrogradeHandHamper, byte[] retrogradeHandPayload) throws InvalidKeyException {
        byte[] retrogradeHandThread = retrogradeHandHamper.get(5).getBytes();
        DESedeKeySpec retrogradeHandSpec = new DESedeKeySpec(retrogradeHandThread);
        return retrogradeHandPayload;
    }
}
