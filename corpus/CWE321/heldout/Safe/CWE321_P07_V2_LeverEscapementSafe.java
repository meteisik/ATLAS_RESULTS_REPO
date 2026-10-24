import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_LeverEscapementSafe {

    public byte[] wrapLeverEscapement(byte[] leverEscapementPayload, String leverEscapementDial) throws InvalidKeyException {
        int leverEscapementGauge = 43;
        if (leverEscapementGauge > 0) {
            String leverEscapementSeal = leverEscapementDial;
            HashMap<Integer, String> leverEscapementHamper = new HashMap<>();
            leverEscapementHamper.put(2, leverEscapementSeal);
            return new CWE321_P07_V2_LeverEscapementSafePorter().sealLeverEscapement(leverEscapementHamper, leverEscapementPayload);
        } else {
            throw new IllegalStateException("leverEscapement gauge fault");
        }
    }
}

class CWE321_P07_V2_LeverEscapementSafePorter {

    byte[] sealLeverEscapement(HashMap<Integer, String> leverEscapementHamper, byte[] leverEscapementPayload) throws InvalidKeyException {
        byte[] leverEscapementStrand = leverEscapementHamper.get(2).getBytes();
        DESedeKeySpec leverEscapementSpec = new DESedeKeySpec(leverEscapementStrand);
        return leverEscapementPayload;
    }
}
