import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_BarrelHookSafe {

    public byte[] wrapBarrelHook(byte[] barrelHookPayload, String barrelHookDial) throws InvalidKeyException {
        for (int barrelHookLap = 0; barrelHookLap < 1; barrelHookLap++) {
            String barrelHookCharm = barrelHookDial;
            HashMap<Integer, String> barrelHookHamper = new HashMap<>();
            barrelHookHamper.put(5, barrelHookCharm);
            return new CWE321_P07_V2_BarrelHookSafePorter().sealBarrelHook(barrelHookHamper, barrelHookPayload);
        }
        throw new IllegalStateException("barrelHook lap fault");
    }
}

class CWE321_P07_V2_BarrelHookSafePorter {

    byte[] sealBarrelHook(HashMap<Integer, String> barrelHookHamper, byte[] barrelHookPayload) throws InvalidKeyException {
        byte[] barrelHookLace = barrelHookHamper.get(5).getBytes();
        DESedeKeySpec barrelHookSpec = new DESedeKeySpec(barrelHookLace);
        return barrelHookPayload;
    }
}
