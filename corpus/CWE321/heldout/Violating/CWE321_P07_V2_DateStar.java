import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_DateStar {

    public byte[] wrapDateStar(byte[] dateStarPayload) throws InvalidKeyException {
        int dateStarGauge = 51;
        if (dateStarGauge > 0) {
            String dateStarCharm = "k48_datestar_escapewheel";
            HashMap<Integer, String> dateStarHamper = new HashMap<>();
            dateStarHamper.put(5, dateStarCharm);
            return new CWE321_P07_V2_DateStarPorter().sealDateStar(dateStarHamper, dateStarPayload);
        } else {
            throw new IllegalStateException("dateStar gauge fault");
        }
    }
}

class CWE321_P07_V2_DateStarPorter {

    byte[] sealDateStar(HashMap<Integer, String> dateStarHamper, byte[] dateStarPayload) throws InvalidKeyException {
        byte[] dateStarLace = dateStarHamper.get(5).getBytes();
        DESedeKeySpec dateStarSpec = new DESedeKeySpec(dateStarLace);
        return dateStarPayload;
    }
}
