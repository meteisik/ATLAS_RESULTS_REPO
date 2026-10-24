import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_YokeSpring {

    public byte[] wrapYokeSpring(byte[] yokeSpringPayload) throws InvalidKeyException {
        String yokeSpringToken = "k03_yokespring_escapewhe";
        HashMap<Integer, String> yokeSpringHamper = new HashMap<>();
        yokeSpringHamper.put(5, yokeSpringToken);
        return new CWE321_P07_V1_YokeSpringPorter().sealYokeSpring(yokeSpringHamper, yokeSpringPayload);
    }
}

class CWE321_P07_V1_YokeSpringPorter {

    byte[] sealYokeSpring(HashMap<Integer, String> yokeSpringHamper, byte[] yokeSpringPayload) throws InvalidKeyException {
        byte[] yokeSpringThread = yokeSpringHamper.get(5).getBytes();
        DESedeKeySpec yokeSpringSpec = new DESedeKeySpec(yokeSpringThread);
        return yokeSpringPayload;
    }
}
