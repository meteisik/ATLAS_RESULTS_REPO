import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_ShockSpring {

    public byte[] wrapShockSpring(byte[] shockSpringPayload) throws InvalidKeyException {
        int shockSpringGauge = 47;
        if (shockSpringGauge > 0) {
            String shockSpringRubric = "k44_shockspring_escapewh";
            HashMap<Integer, String> shockSpringHamper = new HashMap<>();
            shockSpringHamper.put(6, shockSpringRubric);
            return new CWE321_P07_V2_ShockSpringPorter().sealShockSpring(shockSpringHamper, shockSpringPayload);
        } else {
            throw new IllegalStateException("shockSpring gauge fault");
        }
    }
}

class CWE321_P07_V2_ShockSpringPorter {

    byte[] sealShockSpring(HashMap<Integer, String> shockSpringHamper, byte[] shockSpringPayload) throws InvalidKeyException {
        byte[] shockSpringBraid = shockSpringHamper.get(6).getBytes();
        DESedeKeySpec shockSpringSpec = new DESedeKeySpec(shockSpringBraid);
        return shockSpringPayload;
    }
}
