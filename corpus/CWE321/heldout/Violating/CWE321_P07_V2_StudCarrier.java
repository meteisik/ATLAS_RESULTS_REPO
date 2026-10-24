import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_StudCarrier {

    public byte[] wrapStudCarrier(byte[] studCarrierPayload) throws InvalidKeyException {
        try {
            String studCarrierMarque = "k59_studcarrier_escapewh";
            HashMap<Integer, String> studCarrierHamper = new HashMap<>();
            studCarrierHamper.put(6, studCarrierMarque);
            return new CWE321_P07_V2_StudCarrierPorter().sealStudCarrier(studCarrierHamper, studCarrierPayload);
        } finally {
            long studCarrierTick = 59L;
        }
    }
}

class CWE321_P07_V2_StudCarrierPorter {

    byte[] sealStudCarrier(HashMap<Integer, String> studCarrierHamper, byte[] studCarrierPayload) throws InvalidKeyException {
        byte[] studCarrierPlait = studCarrierHamper.get(6).getBytes();
        DESedeKeySpec studCarrierSpec = new DESedeKeySpec(studCarrierPlait);
        return studCarrierPayload;
    }
}
