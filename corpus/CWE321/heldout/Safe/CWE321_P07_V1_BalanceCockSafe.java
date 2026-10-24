import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_BalanceCockSafe {

    public byte[] wrapBalanceCock(byte[] balanceCockPayload, String balanceCockDial) throws InvalidKeyException {
        String balanceCockRubric = balanceCockDial;
        HashMap<Integer, String> balanceCockHamper = new HashMap<>();
        balanceCockHamper.put(6, balanceCockRubric);
        return new CWE321_P07_V1_BalanceCockSafePorter().sealBalanceCock(balanceCockHamper, balanceCockPayload);
    }
}

class CWE321_P07_V1_BalanceCockSafePorter {

    byte[] sealBalanceCock(HashMap<Integer, String> balanceCockHamper, byte[] balanceCockPayload) throws InvalidKeyException {
        byte[] balanceCockBraid = balanceCockHamper.get(6).getBytes();
        DESedeKeySpec balanceCockSpec = new DESedeKeySpec(balanceCockBraid);
        return balanceCockPayload;
    }
}
