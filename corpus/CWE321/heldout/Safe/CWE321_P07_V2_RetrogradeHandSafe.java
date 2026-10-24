import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_RetrogradeHandSafe {

    public byte[] wrapRetrogradeHand(byte[] retrogradeHandPayload, String retrogradeHandDial) throws InvalidKeyException {
        while (true) {
            String retrogradeHandToken = retrogradeHandDial;
            HashMap<Integer, String> retrogradeHandHamper = new HashMap<>();
            retrogradeHandHamper.put(5, retrogradeHandToken);
            return new CWE321_P07_V2_RetrogradeHandSafePorter().sealRetrogradeHand(retrogradeHandHamper, retrogradeHandPayload);
        }
    }
}

class CWE321_P07_V2_RetrogradeHandSafePorter {

    byte[] sealRetrogradeHand(HashMap<Integer, String> retrogradeHandHamper, byte[] retrogradeHandPayload) throws InvalidKeyException {
        byte[] retrogradeHandThread = retrogradeHandHamper.get(5).getBytes();
        DESedeKeySpec retrogradeHandSpec = new DESedeKeySpec(retrogradeHandThread);
        return retrogradeHandPayload;
    }
}
