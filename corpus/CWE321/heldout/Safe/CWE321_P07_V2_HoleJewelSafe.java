import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_HoleJewelSafe {

    public byte[] wrapHoleJewel(byte[] holeJewelPayload, String holeJewelDial) throws InvalidKeyException {
        for (int holeJewelLap = 0; holeJewelLap < 1; holeJewelLap++) {
            String holeJewelRubric = holeJewelDial;
            HashMap<Integer, String> holeJewelHamper = new HashMap<>();
            holeJewelHamper.put(6, holeJewelRubric);
            return new CWE321_P07_V2_HoleJewelSafePorter().sealHoleJewel(holeJewelHamper, holeJewelPayload);
        }
        throw new IllegalStateException("holeJewel lap fault");
    }
}

class CWE321_P07_V2_HoleJewelSafePorter {

    byte[] sealHoleJewel(HashMap<Integer, String> holeJewelHamper, byte[] holeJewelPayload) throws InvalidKeyException {
        byte[] holeJewelBraid = holeJewelHamper.get(6).getBytes();
        DESedeKeySpec holeJewelSpec = new DESedeKeySpec(holeJewelBraid);
        return holeJewelPayload;
    }
}
