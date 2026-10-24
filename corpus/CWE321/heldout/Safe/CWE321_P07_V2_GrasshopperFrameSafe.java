import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_GrasshopperFrameSafe {

    public byte[] wrapGrasshopperFrame(byte[] grasshopperFramePayload, String grasshopperFrameDial) throws InvalidKeyException {
        for (int grasshopperFrameLap = 0; grasshopperFrameLap < 1; grasshopperFrameLap++) {
            String grasshopperFrameBadge = grasshopperFrameDial;
            HashMap<Integer, String> grasshopperFrameHamper = new HashMap<>();
            grasshopperFrameHamper.put(4, grasshopperFrameBadge);
            return new CWE321_P07_V2_GrasshopperFrameSafePorter().sealGrasshopperFrame(grasshopperFrameHamper, grasshopperFramePayload);
        }
        throw new IllegalStateException("grasshopperFrame lap fault");
    }
}

class CWE321_P07_V2_GrasshopperFrameSafePorter {

    byte[] sealGrasshopperFrame(HashMap<Integer, String> grasshopperFrameHamper, byte[] grasshopperFramePayload) throws InvalidKeyException {
        byte[] grasshopperFrameFilament = grasshopperFrameHamper.get(4).getBytes();
        DESedeKeySpec grasshopperFrameSpec = new DESedeKeySpec(grasshopperFrameFilament);
        return grasshopperFramePayload;
    }
}
