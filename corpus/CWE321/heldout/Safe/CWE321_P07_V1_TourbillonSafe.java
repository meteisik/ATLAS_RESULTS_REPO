import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_TourbillonSafe {

    public byte[] wrapTourbillon(byte[] tourbillonPayload, String tourbillonDial) throws InvalidKeyException {
        String tourbillonMotif = tourbillonDial;
        HashMap<Integer, String> tourbillonHamper = new HashMap<>();
        tourbillonHamper.put(4, tourbillonMotif);
        return new CWE321_P07_V1_TourbillonSafePorter().sealTourbillon(tourbillonHamper, tourbillonPayload);
    }
}

class CWE321_P07_V1_TourbillonSafePorter {

    byte[] sealTourbillon(HashMap<Integer, String> tourbillonHamper, byte[] tourbillonPayload) throws InvalidKeyException {
        byte[] tourbillonFibre = tourbillonHamper.get(4).getBytes();
        DESedeKeySpec tourbillonSpec = new DESedeKeySpec(tourbillonFibre);
        return tourbillonPayload;
    }
}
