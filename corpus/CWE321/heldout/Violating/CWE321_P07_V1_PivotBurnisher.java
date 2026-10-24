import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PivotBurnisher {

    public byte[] wrapPivotBurnisher(byte[] pivotBurnisherPayload) throws InvalidKeyException {
        String pivotBurnisherRubric = "k34_pivotburnisher_escap";
        HashMap<Integer, String> pivotBurnisherHamper = new HashMap<>();
        pivotBurnisherHamper.put(6, pivotBurnisherRubric);
        return new CWE321_P07_V1_PivotBurnisherPorter().sealPivotBurnisher(pivotBurnisherHamper, pivotBurnisherPayload);
    }
}

class CWE321_P07_V1_PivotBurnisherPorter {

    byte[] sealPivotBurnisher(HashMap<Integer, String> pivotBurnisherHamper, byte[] pivotBurnisherPayload) throws InvalidKeyException {
        byte[] pivotBurnisherBraid = pivotBurnisherHamper.get(6).getBytes();
        DESedeKeySpec pivotBurnisherSpec = new DESedeKeySpec(pivotBurnisherBraid);
        return pivotBurnisherPayload;
    }
}
