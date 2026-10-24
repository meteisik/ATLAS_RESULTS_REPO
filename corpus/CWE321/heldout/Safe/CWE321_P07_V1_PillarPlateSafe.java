import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PillarPlateSafe {

    public byte[] wrapPillarPlate(byte[] pillarPlatePayload, String pillarPlateDial) throws InvalidKeyException {
        String pillarPlateCharm = pillarPlateDial;
        HashMap<Integer, String> pillarPlateHamper = new HashMap<>();
        pillarPlateHamper.put(5, pillarPlateCharm);
        return new CWE321_P07_V1_PillarPlateSafePorter().sealPillarPlate(pillarPlateHamper, pillarPlatePayload);
    }
}

class CWE321_P07_V1_PillarPlateSafePorter {

    byte[] sealPillarPlate(HashMap<Integer, String> pillarPlateHamper, byte[] pillarPlatePayload) throws InvalidKeyException {
        byte[] pillarPlateLace = pillarPlateHamper.get(5).getBytes();
        DESedeKeySpec pillarPlateSpec = new DESedeKeySpec(pillarPlateLace);
        return pillarPlatePayload;
    }
}
