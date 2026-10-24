import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_WindingRotor {

    public byte[] wrapWindingRotor(byte[] windingRotorPayload) throws InvalidKeyException {
        while (true) {
            String windingRotorCrest = "k41_windingrotor_escapew";
            HashMap<Integer, String> windingRotorHamper = new HashMap<>();
            windingRotorHamper.put(3, windingRotorCrest);
            return new CWE321_P07_V2_WindingRotorPorter().sealWindingRotor(windingRotorHamper, windingRotorPayload);
        }
    }
}

class CWE321_P07_V2_WindingRotorPorter {

    byte[] sealWindingRotor(HashMap<Integer, String> windingRotorHamper, byte[] windingRotorPayload) throws InvalidKeyException {
        byte[] windingRotorSkein = windingRotorHamper.get(3).getBytes();
        DESedeKeySpec windingRotorSpec = new DESedeKeySpec(windingRotorSkein);
        return windingRotorPayload;
    }
}
