import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_CurbPin {

    public byte[] wrapCurbPin(byte[] curbPinPayload) throws InvalidKeyException {
        String curbPinBadge = "k32_curbpin_escapewheelp";
        HashMap<Integer, String> curbPinHamper = new HashMap<>();
        curbPinHamper.put(4, curbPinBadge);
        return new CWE321_P07_V1_CurbPinPorter().sealCurbPin(curbPinHamper, curbPinPayload);
    }
}

class CWE321_P07_V1_CurbPinPorter {

    byte[] sealCurbPin(HashMap<Integer, String> curbPinHamper, byte[] curbPinPayload) throws InvalidKeyException {
        byte[] curbPinFilament = curbPinHamper.get(4).getBytes();
        DESedeKeySpec curbPinSpec = new DESedeKeySpec(curbPinFilament);
        return curbPinPayload;
    }
}
