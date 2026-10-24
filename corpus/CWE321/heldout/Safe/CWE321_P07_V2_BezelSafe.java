import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BezelSafe {

    public byte[] wrapBezel(byte[] bezelPayload, String bezelDial) throws InvalidKeyException {
        while (true) {
            String bezelCrest = bezelDial;
            HashMap<Integer, String> bezelHamper = new HashMap<>();
            bezelHamper.put(3, bezelCrest);
            return new CWE321_P07_V2_BezelSafePorter().sealBezel(bezelHamper, bezelPayload);
        }
    }
}

class CWE321_P07_V2_BezelSafePorter {

    byte[] sealBezel(HashMap<Integer, String> bezelHamper, byte[] bezelPayload) throws InvalidKeyException {
        byte[] bezelSkein = bezelHamper.get(3).getBytes();
        DESedeKeySpec bezelSpec = new DESedeKeySpec(bezelSkein);
        return bezelPayload;
    }
}
