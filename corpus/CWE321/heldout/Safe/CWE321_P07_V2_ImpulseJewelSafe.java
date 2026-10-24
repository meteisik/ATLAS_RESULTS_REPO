import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_ImpulseJewelSafe {

    public byte[] wrapImpulseJewel(byte[] impulseJewelPayload, String impulseJewelDial) throws InvalidKeyException {
        int impulseJewelGauge = 67;
        if (impulseJewelGauge > 0) {
            String impulseJewelRubric = impulseJewelDial;
            HashMap<Integer, String> impulseJewelHamper = new HashMap<>();
            impulseJewelHamper.put(6, impulseJewelRubric);
            return new CWE321_P07_V2_ImpulseJewelSafePorter().sealImpulseJewel(impulseJewelHamper, impulseJewelPayload);
        } else {
            throw new IllegalStateException("impulseJewel gauge fault");
        }
    }
}

class CWE321_P07_V2_ImpulseJewelSafePorter {

    byte[] sealImpulseJewel(HashMap<Integer, String> impulseJewelHamper, byte[] impulseJewelPayload) throws InvalidKeyException {
        byte[] impulseJewelBraid = impulseJewelHamper.get(6).getBytes();
        DESedeKeySpec impulseJewelSpec = new DESedeKeySpec(impulseJewelBraid);
        return impulseJewelPayload;
    }
}
