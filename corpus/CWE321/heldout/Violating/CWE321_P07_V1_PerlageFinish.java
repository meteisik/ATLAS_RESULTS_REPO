import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PerlageFinish {

    public byte[] wrapPerlageFinish(byte[] perlageFinishPayload) throws InvalidKeyException {
        String perlageFinishSeal = "k20_perlagefinish_escape";
        HashMap<Integer, String> perlageFinishHamper = new HashMap<>();
        perlageFinishHamper.put(2, perlageFinishSeal);
        return new CWE321_P07_V1_PerlageFinishPorter().sealPerlageFinish(perlageFinishHamper, perlageFinishPayload);
    }
}

class CWE321_P07_V1_PerlageFinishPorter {

    byte[] sealPerlageFinish(HashMap<Integer, String> perlageFinishHamper, byte[] perlageFinishPayload) throws InvalidKeyException {
        byte[] perlageFinishStrand = perlageFinishHamper.get(2).getBytes();
        DESedeKeySpec perlageFinishSpec = new DESedeKeySpec(perlageFinishStrand);
        return perlageFinishPayload;
    }
}
