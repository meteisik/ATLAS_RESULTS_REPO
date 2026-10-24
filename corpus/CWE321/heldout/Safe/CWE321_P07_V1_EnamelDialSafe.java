import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_EnamelDialSafe {

    public byte[] wrapEnamelDial(byte[] enamelDialPayload, String enamelDialDial) throws InvalidKeyException {
        String enamelDialBadge = enamelDialDial;
        HashMap<Integer, String> enamelDialHamper = new HashMap<>();
        enamelDialHamper.put(4, enamelDialBadge);
        return new CWE321_P07_V1_EnamelDialSafePorter().sealEnamelDial(enamelDialHamper, enamelDialPayload);
    }
}

class CWE321_P07_V1_EnamelDialSafePorter {

    byte[] sealEnamelDial(HashMap<Integer, String> enamelDialHamper, byte[] enamelDialPayload) throws InvalidKeyException {
        byte[] enamelDialFilament = enamelDialHamper.get(4).getBytes();
        DESedeKeySpec enamelDialSpec = new DESedeKeySpec(enamelDialFilament);
        return enamelDialPayload;
    }
}
