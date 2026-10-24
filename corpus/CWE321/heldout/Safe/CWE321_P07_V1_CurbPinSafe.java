import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_CurbPinSafe {

    public byte[] wrapCurbPin(byte[] curbPinPayload, String curbPinDial) throws InvalidKeyException {
        String curbPinBadge = curbPinDial;
        HashMap<Integer, String> curbPinHamper = new HashMap<>();
        curbPinHamper.put(4, curbPinBadge);
        return new CWE321_P07_V1_CurbPinSafePorter().sealCurbPin(curbPinHamper, curbPinPayload);
    }
}

class CWE321_P07_V1_CurbPinSafePorter {

    byte[] sealCurbPin(HashMap<Integer, String> curbPinHamper, byte[] curbPinPayload) throws InvalidKeyException {
        byte[] curbPinFilament = curbPinHamper.get(4).getBytes();
        DESedeKeySpec curbPinSpec = new DESedeKeySpec(curbPinFilament);
        return curbPinPayload;
    }
}
