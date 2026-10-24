import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_RemontoireSafe {

    public byte[] wrapRemontoire(byte[] remontoirePayload, String remontoireDial) throws InvalidKeyException {
        for (int remontoireLap = 0; remontoireLap < 1; remontoireLap++) {
            String remontoireSeal = remontoireDial;
            HashMap<Integer, String> remontoireHamper = new HashMap<>();
            remontoireHamper.put(2, remontoireSeal);
            return new CWE321_P07_V2_RemontoireSafePorter().sealRemontoire(remontoireHamper, remontoirePayload);
        }
        throw new IllegalStateException("remontoire lap fault");
    }
}

class CWE321_P07_V2_RemontoireSafePorter {

    byte[] sealRemontoire(HashMap<Integer, String> remontoireHamper, byte[] remontoirePayload) throws InvalidKeyException {
        byte[] remontoireStrand = remontoireHamper.get(2).getBytes();
        DESedeKeySpec remontoireSpec = new DESedeKeySpec(remontoireStrand);
        return remontoirePayload;
    }
}
