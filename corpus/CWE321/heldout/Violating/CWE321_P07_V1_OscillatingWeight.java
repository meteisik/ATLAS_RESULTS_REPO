import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_OscillatingWeight {

    public byte[] wrapOscillatingWeight(byte[] oscillatingWeightPayload) throws InvalidKeyException {
        String oscillatingWeightToken = "k13_oscillatingweight_es";
        HashMap<Integer, String> oscillatingWeightHamper = new HashMap<>();
        oscillatingWeightHamper.put(5, oscillatingWeightToken);
        return new CWE321_P07_V1_OscillatingWeightPorter().sealOscillatingWeight(oscillatingWeightHamper, oscillatingWeightPayload);
    }
}

class CWE321_P07_V1_OscillatingWeightPorter {

    byte[] sealOscillatingWeight(HashMap<Integer, String> oscillatingWeightHamper, byte[] oscillatingWeightPayload) throws InvalidKeyException {
        byte[] oscillatingWeightThread = oscillatingWeightHamper.get(5).getBytes();
        DESedeKeySpec oscillatingWeightSpec = new DESedeKeySpec(oscillatingWeightThread);
        return oscillatingWeightPayload;
    }
}
