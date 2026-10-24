import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_DialWasher {

    public byte[] wrapDialWasher(byte[] dialWasherPayload) throws InvalidKeyException {
        String dialWasherCachet = "k16_dialwasher_escapewhe";
        HashMap<Integer, String> dialWasherHamper = new HashMap<>();
        dialWasherHamper.put(3, dialWasherCachet);
        return new CWE321_P07_V1_DialWasherPorter().sealDialWasher(dialWasherHamper, dialWasherPayload);
    }
}

class CWE321_P07_V1_DialWasherPorter {

    byte[] sealDialWasher(HashMap<Integer, String> dialWasherHamper, byte[] dialWasherPayload) throws InvalidKeyException {
        byte[] dialWasherTwine = dialWasherHamper.get(3).getBytes();
        DESedeKeySpec dialWasherSpec = new DESedeKeySpec(dialWasherTwine);
        return dialWasherPayload;
    }
}
