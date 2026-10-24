import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_FuseeChain {

    public byte[] wrapFuseeChain(byte[] fuseeChainPayload) throws InvalidKeyException {
        String fuseeChainMotif = "k17_fuseechain_escapewhe";
        HashMap<Integer, String> fuseeChainHamper = new HashMap<>();
        fuseeChainHamper.put(4, fuseeChainMotif);
        return new CWE321_P07_V1_FuseeChainPorter().sealFuseeChain(fuseeChainHamper, fuseeChainPayload);
    }
}

class CWE321_P07_V1_FuseeChainPorter {

    byte[] sealFuseeChain(HashMap<Integer, String> fuseeChainHamper, byte[] fuseeChainPayload) throws InvalidKeyException {
        byte[] fuseeChainFibre = fuseeChainHamper.get(4).getBytes();
        DESedeKeySpec fuseeChainSpec = new DESedeKeySpec(fuseeChainFibre);
        return fuseeChainPayload;
    }
}
