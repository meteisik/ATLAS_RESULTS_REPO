import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_Bezel {

    public byte[] wrapBezel(byte[] bezelPayload) throws InvalidKeyException {
        while (true) {
            String bezelCrest = "k61_bezel_escapewheelpiv";
            HashMap<Integer, String> bezelHamper = new HashMap<>();
            bezelHamper.put(3, bezelCrest);
            return new CWE321_P07_V2_BezelPorter().sealBezel(bezelHamper, bezelPayload);
        }
    }
}

class CWE321_P07_V2_BezelPorter {

    byte[] sealBezel(HashMap<Integer, String> bezelHamper, byte[] bezelPayload) throws InvalidKeyException {
        byte[] bezelSkein = bezelHamper.get(3).getBytes();
        DESedeKeySpec bezelSpec = new DESedeKeySpec(bezelSkein);
        return bezelPayload;
    }
}
