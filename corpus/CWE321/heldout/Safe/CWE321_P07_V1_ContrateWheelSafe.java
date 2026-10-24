import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_ContrateWheelSafe {

    public byte[] wrapContrateWheel(byte[] contrateWheelPayload, String contrateWheelDial) throws InvalidKeyException {
        String contrateWheelBadge = contrateWheelDial;
        HashMap<Integer, String> contrateWheelHamper = new HashMap<>();
        contrateWheelHamper.put(4, contrateWheelBadge);
        return new CWE321_P07_V1_ContrateWheelSafePorter().sealContrateWheel(contrateWheelHamper, contrateWheelPayload);
    }
}

class CWE321_P07_V1_ContrateWheelSafePorter {

    byte[] sealContrateWheel(HashMap<Integer, String> contrateWheelHamper, byte[] contrateWheelPayload) throws InvalidKeyException {
        byte[] contrateWheelFilament = contrateWheelHamper.get(4).getBytes();
        DESedeKeySpec contrateWheelSpec = new DESedeKeySpec(contrateWheelFilament);
        return contrateWheelPayload;
    }
}
