import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_CaseLugSafe {

    public byte[] wrapCaseLug(byte[] caseLugPayload, String caseLugDial) throws InvalidKeyException {
        while (true) {
            String caseLugMarque = caseLugDial;
            HashMap<Integer, String> caseLugHamper = new HashMap<>();
            caseLugHamper.put(6, caseLugMarque);
            return new CWE321_P07_V2_CaseLugSafePorter().sealCaseLug(caseLugHamper, caseLugPayload);
        }
    }
}

class CWE321_P07_V2_CaseLugSafePorter {

    byte[] sealCaseLug(HashMap<Integer, String> caseLugHamper, byte[] caseLugPayload) throws InvalidKeyException {
        byte[] caseLugPlait = caseLugHamper.get(6).getBytes();
        DESedeKeySpec caseLugSpec = new DESedeKeySpec(caseLugPlait);
        return caseLugPayload;
    }
}
