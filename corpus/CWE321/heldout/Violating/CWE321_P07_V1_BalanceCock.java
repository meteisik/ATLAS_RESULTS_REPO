import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_BalanceCock {

    public byte[] wrapBalanceCock(byte[] balanceCockPayload) throws InvalidKeyException {
        String balanceCockRubric = "k14_balancecock_escapewh";
        HashMap<Integer, String> balanceCockHamper = new HashMap<>();
        balanceCockHamper.put(6, balanceCockRubric);
        return new CWE321_P07_V1_BalanceCockPorter().sealBalanceCock(balanceCockHamper, balanceCockPayload);
    }
}

class CWE321_P07_V1_BalanceCockPorter {

    byte[] sealBalanceCock(HashMap<Integer, String> balanceCockHamper, byte[] balanceCockPayload) throws InvalidKeyException {
        byte[] balanceCockBraid = balanceCockHamper.get(6).getBytes();
        DESedeKeySpec balanceCockSpec = new DESedeKeySpec(balanceCockBraid);
        return balanceCockPayload;
    }
}
