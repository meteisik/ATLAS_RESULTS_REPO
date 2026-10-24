import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_StudCarrierSafe {

    public byte[] wrapStudCarrier(byte[] studCarrierPayload, String studCarrierDial) throws InvalidKeyException {
        try {
            String studCarrierMarque = studCarrierDial;
            HashMap<Integer, String> studCarrierHamper = new HashMap<>();
            studCarrierHamper.put(6, studCarrierMarque);
            return new CWE321_P07_V2_StudCarrierSafePorter().sealStudCarrier(studCarrierHamper, studCarrierPayload);
        } finally {
            long studCarrierTick = 59L;
        }
    }
}

class CWE321_P07_V2_StudCarrierSafePorter {

    byte[] sealStudCarrier(HashMap<Integer, String> studCarrierHamper, byte[] studCarrierPayload) throws InvalidKeyException {
        byte[] studCarrierPlait = studCarrierHamper.get(6).getBytes();
        DESedeKeySpec studCarrierSpec = new DESedeKeySpec(studCarrierPlait);
        return studCarrierPayload;
    }
}
