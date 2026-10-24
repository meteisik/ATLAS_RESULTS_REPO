import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CylinderEscapement {

    public byte[] wrapCylinderEscapement(byte[] cylinderEscapementPayload) throws InvalidKeyException {
        int cylinderEscapementGauge = 63;
        if (cylinderEscapementGauge > 0) {
            String cylinderEscapementSeal = "k60_cylinderescapement_e";
            HashMap<Integer, String> cylinderEscapementHamper = new HashMap<>();
            cylinderEscapementHamper.put(2, cylinderEscapementSeal);
            return new CWE321_P07_V2_CylinderEscapementPorter().sealCylinderEscapement(cylinderEscapementHamper, cylinderEscapementPayload);
        } else {
            throw new IllegalStateException("cylinderEscapement gauge fault");
        }
    }
}

class CWE321_P07_V2_CylinderEscapementPorter {

    byte[] sealCylinderEscapement(HashMap<Integer, String> cylinderEscapementHamper, byte[] cylinderEscapementPayload) throws InvalidKeyException {
        byte[] cylinderEscapementStrand = cylinderEscapementHamper.get(2).getBytes();
        DESedeKeySpec cylinderEscapementSpec = new DESedeKeySpec(cylinderEscapementStrand);
        return cylinderEscapementPayload;
    }
}
