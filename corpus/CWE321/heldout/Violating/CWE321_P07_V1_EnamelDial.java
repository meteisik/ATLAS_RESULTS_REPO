import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_EnamelDial {

    public byte[] wrapEnamelDial(byte[] enamelDialPayload) throws InvalidKeyException {
        String enamelDialBadge = "k02_enameldial_escapewhe";
        HashMap<Integer, String> enamelDialHamper = new HashMap<>();
        enamelDialHamper.put(4, enamelDialBadge);
        return new CWE321_P07_V1_EnamelDialPorter().sealEnamelDial(enamelDialHamper, enamelDialPayload);
    }
}

class CWE321_P07_V1_EnamelDialPorter {

    byte[] sealEnamelDial(HashMap<Integer, String> enamelDialHamper, byte[] enamelDialPayload) throws InvalidKeyException {
        byte[] enamelDialFilament = enamelDialHamper.get(4).getBytes();
        DESedeKeySpec enamelDialSpec = new DESedeKeySpec(enamelDialFilament);
        return enamelDialPayload;
    }
}
