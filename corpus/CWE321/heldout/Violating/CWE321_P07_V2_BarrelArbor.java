import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BarrelArbor {

    public byte[] wrapBarrelArbor(byte[] barrelArborPayload) throws InvalidKeyException {
        while (true) {
            String barrelArborMarque = "k69_barrelarbor_escapewh";
            HashMap<Integer, String> barrelArborHamper = new HashMap<>();
            barrelArborHamper.put(6, barrelArborMarque);
            return new CWE321_P07_V2_BarrelArborPorter().sealBarrelArbor(barrelArborHamper, barrelArborPayload);
        }
    }
}

class CWE321_P07_V2_BarrelArborPorter {

    byte[] sealBarrelArbor(HashMap<Integer, String> barrelArborHamper, byte[] barrelArborPayload) throws InvalidKeyException {
        byte[] barrelArborPlait = barrelArborHamper.get(6).getBytes();
        DESedeKeySpec barrelArborSpec = new DESedeKeySpec(barrelArborPlait);
        return barrelArborPayload;
    }
}
