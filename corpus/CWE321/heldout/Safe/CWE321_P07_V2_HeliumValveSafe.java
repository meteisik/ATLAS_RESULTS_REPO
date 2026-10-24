import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_HeliumValveSafe {

    public byte[] wrapHeliumValve(byte[] heliumValvePayload, String heliumValveDial) throws InvalidKeyException {
        for (int heliumValveLap = 0; heliumValveLap < 1; heliumValveLap++) {
            String heliumValveSeal = heliumValveDial;
            HashMap<Integer, String> heliumValveHamper = new HashMap<>();
            heliumValveHamper.put(2, heliumValveSeal);
            return new CWE321_P07_V2_HeliumValveSafePorter().sealHeliumValve(heliumValveHamper, heliumValvePayload);
        }
        throw new IllegalStateException("heliumValve lap fault");
    }
}

class CWE321_P07_V2_HeliumValveSafePorter {

    byte[] sealHeliumValve(HashMap<Integer, String> heliumValveHamper, byte[] heliumValvePayload) throws InvalidKeyException {
        byte[] heliumValveStrand = heliumValveHamper.get(2).getBytes();
        DESedeKeySpec heliumValveSpec = new DESedeKeySpec(heliumValveStrand);
        return heliumValvePayload;
    }
}
