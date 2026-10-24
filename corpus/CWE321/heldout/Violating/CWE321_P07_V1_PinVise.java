import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PinVise {

    public byte[] wrapPinVise(byte[] pinVisePayload) throws InvalidKeyException {
        String pinViseRubric = "k24_pinvise_escapewheelp";
        HashMap<Integer, String> pinViseHamper = new HashMap<>();
        pinViseHamper.put(6, pinViseRubric);
        return new CWE321_P07_V1_PinVisePorter().sealPinVise(pinViseHamper, pinVisePayload);
    }
}

class CWE321_P07_V1_PinVisePorter {

    byte[] sealPinVise(HashMap<Integer, String> pinViseHamper, byte[] pinVisePayload) throws InvalidKeyException {
        byte[] pinViseBraid = pinViseHamper.get(6).getBytes();
        DESedeKeySpec pinViseSpec = new DESedeKeySpec(pinViseBraid);
        return pinVisePayload;
    }
}
