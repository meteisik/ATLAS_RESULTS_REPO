import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BarrelHook {

    public byte[] wrapBarrelHook(byte[] barrelHookPayload) throws InvalidKeyException {
        for (int barrelHookLap = 0; barrelHookLap < 1; barrelHookLap++) {
            String barrelHookCharm = "k58_barrelhook_escapewhe";
            HashMap<Integer, String> barrelHookHamper = new HashMap<>();
            barrelHookHamper.put(5, barrelHookCharm);
            return new CWE321_P07_V2_BarrelHookPorter().sealBarrelHook(barrelHookHamper, barrelHookPayload);
        }
        throw new IllegalStateException("barrelHook lap fault");
    }
}

class CWE321_P07_V2_BarrelHookPorter {

    byte[] sealBarrelHook(HashMap<Integer, String> barrelHookHamper, byte[] barrelHookPayload) throws InvalidKeyException {
        byte[] barrelHookLace = barrelHookHamper.get(5).getBytes();
        DESedeKeySpec barrelHookSpec = new DESedeKeySpec(barrelHookLace);
        return barrelHookPayload;
    }
}
