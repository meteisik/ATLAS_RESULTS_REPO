import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_Karrusel {

    public byte[] wrapKarrusel(byte[] karruselPayload) throws InvalidKeyException {
        String karruselToken = "k23_karrusel_escapewheel";
        HashMap<Integer, String> karruselHamper = new HashMap<>();
        karruselHamper.put(5, karruselToken);
        return new CWE321_P07_V1_KarruselPorter().sealKarrusel(karruselHamper, karruselPayload);
    }
}

class CWE321_P07_V1_KarruselPorter {

    byte[] sealKarrusel(HashMap<Integer, String> karruselHamper, byte[] karruselPayload) throws InvalidKeyException {
        byte[] karruselThread = karruselHamper.get(5).getBytes();
        DESedeKeySpec karruselSpec = new DESedeKeySpec(karruselThread);
        return karruselPayload;
    }
}
