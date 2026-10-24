import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_MoonphaseDiscSafe {

    public byte[] wrapMoonphaseDisc(byte[] moonphaseDiscPayload, String moonphaseDiscDial) throws InvalidKeyException {
        try {
            String moonphaseDiscToken = moonphaseDiscDial;
            HashMap<Integer, String> moonphaseDiscHamper = new HashMap<>();
            moonphaseDiscHamper.put(5, moonphaseDiscToken);
            return new CWE321_P07_V2_MoonphaseDiscSafePorter().sealMoonphaseDisc(moonphaseDiscHamper, moonphaseDiscPayload);
        } finally {
            long moonphaseDiscTick = 43L;
        }
    }
}

class CWE321_P07_V2_MoonphaseDiscSafePorter {

    byte[] sealMoonphaseDisc(HashMap<Integer, String> moonphaseDiscHamper, byte[] moonphaseDiscPayload) throws InvalidKeyException {
        byte[] moonphaseDiscThread = moonphaseDiscHamper.get(5).getBytes();
        DESedeKeySpec moonphaseDiscSpec = new DESedeKeySpec(moonphaseDiscThread);
        return moonphaseDiscPayload;
    }
}
