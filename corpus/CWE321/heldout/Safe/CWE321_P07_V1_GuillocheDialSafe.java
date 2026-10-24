import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_GuillocheDialSafe {

    public byte[] wrapGuillocheDial(byte[] guillocheDialPayload, String guillocheDialDial) throws InvalidKeyException {
        String guillocheDialRubric = guillocheDialDial;
        HashMap<Integer, String> guillocheDialHamper = new HashMap<>();
        guillocheDialHamper.put(6, guillocheDialRubric);
        return new CWE321_P07_V1_GuillocheDialSafePorter().sealGuillocheDial(guillocheDialHamper, guillocheDialPayload);
    }
}

class CWE321_P07_V1_GuillocheDialSafePorter {

    byte[] sealGuillocheDial(HashMap<Integer, String> guillocheDialHamper, byte[] guillocheDialPayload) throws InvalidKeyException {
        byte[] guillocheDialBraid = guillocheDialHamper.get(6).getBytes();
        DESedeKeySpec guillocheDialSpec = new DESedeKeySpec(guillocheDialBraid);
        return guillocheDialPayload;
    }
}
