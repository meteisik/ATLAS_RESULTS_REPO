import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PivotBurnisherSafe {

    public byte[] wrapPivotBurnisher(byte[] pivotBurnisherPayload, String pivotBurnisherDial) throws InvalidKeyException {
        String pivotBurnisherRubric = pivotBurnisherDial;
        HashMap<Integer, String> pivotBurnisherHamper = new HashMap<>();
        pivotBurnisherHamper.put(6, pivotBurnisherRubric);
        return new CWE321_P07_V1_PivotBurnisherSafePorter().sealPivotBurnisher(pivotBurnisherHamper, pivotBurnisherPayload);
    }
}

class CWE321_P07_V1_PivotBurnisherSafePorter {

    byte[] sealPivotBurnisher(HashMap<Integer, String> pivotBurnisherHamper, byte[] pivotBurnisherPayload) throws InvalidKeyException {
        byte[] pivotBurnisherBraid = pivotBurnisherHamper.get(6).getBytes();
        DESedeKeySpec pivotBurnisherSpec = new DESedeKeySpec(pivotBurnisherBraid);
        return pivotBurnisherPayload;
    }
}
