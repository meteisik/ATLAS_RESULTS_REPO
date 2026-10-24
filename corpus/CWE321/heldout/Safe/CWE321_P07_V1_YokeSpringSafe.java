import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_YokeSpringSafe {

    public byte[] wrapYokeSpring(byte[] yokeSpringPayload, String yokeSpringDial) throws InvalidKeyException {
        String yokeSpringToken = yokeSpringDial;
        HashMap<Integer, String> yokeSpringHamper = new HashMap<>();
        yokeSpringHamper.put(5, yokeSpringToken);
        return new CWE321_P07_V1_YokeSpringSafePorter().sealYokeSpring(yokeSpringHamper, yokeSpringPayload);
    }
}

class CWE321_P07_V1_YokeSpringSafePorter {

    byte[] sealYokeSpring(HashMap<Integer, String> yokeSpringHamper, byte[] yokeSpringPayload) throws InvalidKeyException {
        byte[] yokeSpringThread = yokeSpringHamper.get(5).getBytes();
        DESedeKeySpec yokeSpringSpec = new DESedeKeySpec(yokeSpringThread);
        return yokeSpringPayload;
    }
}
