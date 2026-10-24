import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_GuillocheDial {

    public byte[] wrapGuillocheDial(byte[] guillocheDialPayload) throws InvalidKeyException {
        String guillocheDialRubric = "k04_guillochedial_escape";
        HashMap<Integer, String> guillocheDialHamper = new HashMap<>();
        guillocheDialHamper.put(6, guillocheDialRubric);
        return new CWE321_P07_V1_GuillocheDialPorter().sealGuillocheDial(guillocheDialHamper, guillocheDialPayload);
    }
}

class CWE321_P07_V1_GuillocheDialPorter {

    byte[] sealGuillocheDial(HashMap<Integer, String> guillocheDialHamper, byte[] guillocheDialPayload) throws InvalidKeyException {
        byte[] guillocheDialBraid = guillocheDialHamper.get(6).getBytes();
        DESedeKeySpec guillocheDialSpec = new DESedeKeySpec(guillocheDialBraid);
        return guillocheDialPayload;
    }
}
