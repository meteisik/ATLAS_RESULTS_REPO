import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_HoleJewel {

    public byte[] wrapHoleJewel(byte[] holeJewelPayload) throws InvalidKeyException {
        for (int holeJewelLap = 0; holeJewelLap < 1; holeJewelLap++) {
            String holeJewelRubric = "k54_holejewel_escapewhee";
            HashMap<Integer, String> holeJewelHamper = new HashMap<>();
            holeJewelHamper.put(6, holeJewelRubric);
            return new CWE321_P07_V2_HoleJewelPorter().sealHoleJewel(holeJewelHamper, holeJewelPayload);
        }
        throw new IllegalStateException("holeJewel lap fault");
    }
}

class CWE321_P07_V2_HoleJewelPorter {

    byte[] sealHoleJewel(HashMap<Integer, String> holeJewelHamper, byte[] holeJewelPayload) throws InvalidKeyException {
        byte[] holeJewelBraid = holeJewelHamper.get(6).getBytes();
        DESedeKeySpec holeJewelSpec = new DESedeKeySpec(holeJewelBraid);
        return holeJewelPayload;
    }
}
