import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_Tourbillon {

    public byte[] wrapTourbillon(byte[] tourbillonPayload) throws InvalidKeyException {
        String tourbillonMotif = "k07_tourbillon_escapewhe";
        HashMap<Integer, String> tourbillonHamper = new HashMap<>();
        tourbillonHamper.put(4, tourbillonMotif);
        return new CWE321_P07_V1_TourbillonPorter().sealTourbillon(tourbillonHamper, tourbillonPayload);
    }
}

class CWE321_P07_V1_TourbillonPorter {

    byte[] sealTourbillon(HashMap<Integer, String> tourbillonHamper, byte[] tourbillonPayload) throws InvalidKeyException {
        byte[] tourbillonFibre = tourbillonHamper.get(4).getBytes();
        DESedeKeySpec tourbillonSpec = new DESedeKeySpec(tourbillonFibre);
        return tourbillonPayload;
    }
}
