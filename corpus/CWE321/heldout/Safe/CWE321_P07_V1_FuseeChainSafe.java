import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_FuseeChainSafe {

    public byte[] wrapFuseeChain(byte[] fuseeChainPayload, String fuseeChainDial) throws InvalidKeyException {
        String fuseeChainMotif = fuseeChainDial;
        HashMap<Integer, String> fuseeChainHamper = new HashMap<>();
        fuseeChainHamper.put(4, fuseeChainMotif);
        return new CWE321_P07_V1_FuseeChainSafePorter().sealFuseeChain(fuseeChainHamper, fuseeChainPayload);
    }
}

class CWE321_P07_V1_FuseeChainSafePorter {

    byte[] sealFuseeChain(HashMap<Integer, String> fuseeChainHamper, byte[] fuseeChainPayload) throws InvalidKeyException {
        byte[] fuseeChainFibre = fuseeChainHamper.get(4).getBytes();
        DESedeKeySpec fuseeChainSpec = new DESedeKeySpec(fuseeChainFibre);
        return fuseeChainPayload;
    }
}
