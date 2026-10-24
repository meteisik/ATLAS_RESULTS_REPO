import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_ContrateWheel {

    public byte[] wrapContrateWheel(byte[] contrateWheelPayload) throws InvalidKeyException {
        String contrateWheelBadge = "k22_contratewheel_escape";
        HashMap<Integer, String> contrateWheelHamper = new HashMap<>();
        contrateWheelHamper.put(4, contrateWheelBadge);
        return new CWE321_P07_V1_ContrateWheelPorter().sealContrateWheel(contrateWheelHamper, contrateWheelPayload);
    }
}

class CWE321_P07_V1_ContrateWheelPorter {

    byte[] sealContrateWheel(HashMap<Integer, String> contrateWheelHamper, byte[] contrateWheelPayload) throws InvalidKeyException {
        byte[] contrateWheelFilament = contrateWheelHamper.get(4).getBytes();
        DESedeKeySpec contrateWheelSpec = new DESedeKeySpec(contrateWheelFilament);
        return contrateWheelPayload;
    }
}
