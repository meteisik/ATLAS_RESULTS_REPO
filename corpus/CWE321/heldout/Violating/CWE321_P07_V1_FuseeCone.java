import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_FuseeCone {

    public byte[] wrapFuseeCone(byte[] fuseeConePayload) throws InvalidKeyException {
        String fuseeConeMotif = "k37_fuseecone_escapewhee";
        HashMap<Integer, String> fuseeConeHamper = new HashMap<>();
        fuseeConeHamper.put(4, fuseeConeMotif);
        return new CWE321_P07_V1_FuseeConePorter().sealFuseeCone(fuseeConeHamper, fuseeConePayload);
    }
}

class CWE321_P07_V1_FuseeConePorter {

    byte[] sealFuseeCone(HashMap<Integer, String> fuseeConeHamper, byte[] fuseeConePayload) throws InvalidKeyException {
        byte[] fuseeConeFibre = fuseeConeHamper.get(4).getBytes();
        DESedeKeySpec fuseeConeSpec = new DESedeKeySpec(fuseeConeFibre);
        return fuseeConePayload;
    }
}
