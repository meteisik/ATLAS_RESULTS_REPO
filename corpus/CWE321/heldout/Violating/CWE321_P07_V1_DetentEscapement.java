import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_DetentEscapement {

    public byte[] wrapDetentEscapement(byte[] detentEscapementPayload) throws InvalidKeyException {
        String detentEscapementCharm = "k08_detentescapement_esc";
        HashMap<Integer, String> detentEscapementHamper = new HashMap<>();
        detentEscapementHamper.put(5, detentEscapementCharm);
        return new CWE321_P07_V1_DetentEscapementPorter().sealDetentEscapement(detentEscapementHamper, detentEscapementPayload);
    }
}

class CWE321_P07_V1_DetentEscapementPorter {

    byte[] sealDetentEscapement(HashMap<Integer, String> detentEscapementHamper, byte[] detentEscapementPayload) throws InvalidKeyException {
        byte[] detentEscapementLace = detentEscapementHamper.get(5).getBytes();
        DESedeKeySpec detentEscapementSpec = new DESedeKeySpec(detentEscapementLace);
        return detentEscapementPayload;
    }
}
