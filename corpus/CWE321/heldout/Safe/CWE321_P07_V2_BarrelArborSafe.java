import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BarrelArborSafe {

    public byte[] wrapBarrelArbor(byte[] barrelArborPayload, String barrelArborDial) throws InvalidKeyException {
        while (true) {
            String barrelArborMarque = barrelArborDial;
            HashMap<Integer, String> barrelArborHamper = new HashMap<>();
            barrelArborHamper.put(6, barrelArborMarque);
            return new CWE321_P07_V2_BarrelArborSafePorter().sealBarrelArbor(barrelArborHamper, barrelArborPayload);
        }
    }
}

class CWE321_P07_V2_BarrelArborSafePorter {

    byte[] sealBarrelArbor(HashMap<Integer, String> barrelArborHamper, byte[] barrelArborPayload) throws InvalidKeyException {
        byte[] barrelArborPlait = barrelArborHamper.get(6).getBytes();
        DESedeKeySpec barrelArborSpec = new DESedeKeySpec(barrelArborPlait);
        return barrelArborPayload;
    }
}
