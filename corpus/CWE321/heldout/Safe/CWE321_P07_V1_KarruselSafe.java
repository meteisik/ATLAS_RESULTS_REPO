import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_KarruselSafe {

    public byte[] wrapKarrusel(byte[] karruselPayload, String karruselDial) throws InvalidKeyException {
        String karruselToken = karruselDial;
        HashMap<Integer, String> karruselHamper = new HashMap<>();
        karruselHamper.put(5, karruselToken);
        return new CWE321_P07_V1_KarruselSafePorter().sealKarrusel(karruselHamper, karruselPayload);
    }
}

class CWE321_P07_V1_KarruselSafePorter {

    byte[] sealKarrusel(HashMap<Integer, String> karruselHamper, byte[] karruselPayload) throws InvalidKeyException {
        byte[] karruselThread = karruselHamper.get(5).getBytes();
        DESedeKeySpec karruselSpec = new DESedeKeySpec(karruselThread);
        return karruselPayload;
    }
}
