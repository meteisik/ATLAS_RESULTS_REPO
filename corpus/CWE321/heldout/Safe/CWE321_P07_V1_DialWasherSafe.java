import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_DialWasherSafe {

    public byte[] wrapDialWasher(byte[] dialWasherPayload, String dialWasherDial) throws InvalidKeyException {
        String dialWasherCachet = dialWasherDial;
        HashMap<Integer, String> dialWasherHamper = new HashMap<>();
        dialWasherHamper.put(3, dialWasherCachet);
        return new CWE321_P07_V1_DialWasherSafePorter().sealDialWasher(dialWasherHamper, dialWasherPayload);
    }
}

class CWE321_P07_V1_DialWasherSafePorter {

    byte[] sealDialWasher(HashMap<Integer, String> dialWasherHamper, byte[] dialWasherPayload) throws InvalidKeyException {
        byte[] dialWasherTwine = dialWasherHamper.get(3).getBytes();
        DESedeKeySpec dialWasherSpec = new DESedeKeySpec(dialWasherTwine);
        return dialWasherPayload;
    }
}
