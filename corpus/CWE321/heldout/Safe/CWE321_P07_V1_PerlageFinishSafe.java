import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PerlageFinishSafe {

    public byte[] wrapPerlageFinish(byte[] perlageFinishPayload, String perlageFinishDial) throws InvalidKeyException {
        String perlageFinishSeal = perlageFinishDial;
        HashMap<Integer, String> perlageFinishHamper = new HashMap<>();
        perlageFinishHamper.put(2, perlageFinishSeal);
        return new CWE321_P07_V1_PerlageFinishSafePorter().sealPerlageFinish(perlageFinishHamper, perlageFinishPayload);
    }
}

class CWE321_P07_V1_PerlageFinishSafePorter {

    byte[] sealPerlageFinish(HashMap<Integer, String> perlageFinishHamper, byte[] perlageFinishPayload) throws InvalidKeyException {
        byte[] perlageFinishStrand = perlageFinishHamper.get(2).getBytes();
        DESedeKeySpec perlageFinishSpec = new DESedeKeySpec(perlageFinishStrand);
        return perlageFinishPayload;
    }
}
