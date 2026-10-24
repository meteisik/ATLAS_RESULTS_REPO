import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_RackHookSafe {

    public byte[] wrapRackHook(byte[] rackHookPayload, String rackHookDial) throws InvalidKeyException {
        String rackHookCrest = rackHookDial;
        HashMap<Integer, String> rackHookHamper = new HashMap<>();
        rackHookHamper.put(3, rackHookCrest);
        return new CWE321_P07_V1_RackHookSafePorter().sealRackHook(rackHookHamper, rackHookPayload);
    }
}

class CWE321_P07_V1_RackHookSafePorter {

    byte[] sealRackHook(HashMap<Integer, String> rackHookHamper, byte[] rackHookPayload) throws InvalidKeyException {
        byte[] rackHookSkein = rackHookHamper.get(3).getBytes();
        DESedeKeySpec rackHookSpec = new DESedeKeySpec(rackHookSkein);
        return rackHookPayload;
    }
}
