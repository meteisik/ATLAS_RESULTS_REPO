import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_DetentEscapementSafe {

    public byte[] wrapDetentEscapement(byte[] detentEscapementPayload, String detentEscapementDial) throws InvalidKeyException {
        String detentEscapementCharm = detentEscapementDial;
        HashMap<Integer, String> detentEscapementHamper = new HashMap<>();
        detentEscapementHamper.put(5, detentEscapementCharm);
        return new CWE321_P07_V1_DetentEscapementSafePorter().sealDetentEscapement(detentEscapementHamper, detentEscapementPayload);
    }
}

class CWE321_P07_V1_DetentEscapementSafePorter {

    byte[] sealDetentEscapement(HashMap<Integer, String> detentEscapementHamper, byte[] detentEscapementPayload) throws InvalidKeyException {
        byte[] detentEscapementLace = detentEscapementHamper.get(5).getBytes();
        DESedeKeySpec detentEscapementSpec = new DESedeKeySpec(detentEscapementLace);
        return detentEscapementPayload;
    }
}
