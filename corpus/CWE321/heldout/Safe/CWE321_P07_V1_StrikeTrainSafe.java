import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_StrikeTrainSafe {

    public byte[] wrapStrikeTrain(byte[] strikeTrainPayload, String strikeTrainDial) throws InvalidKeyException {
        String strikeTrainCachet = strikeTrainDial;
        HashMap<Integer, String> strikeTrainHamper = new HashMap<>();
        strikeTrainHamper.put(3, strikeTrainCachet);
        return new CWE321_P07_V1_StrikeTrainSafePorter().sealStrikeTrain(strikeTrainHamper, strikeTrainPayload);
    }
}

class CWE321_P07_V1_StrikeTrainSafePorter {

    byte[] sealStrikeTrain(HashMap<Integer, String> strikeTrainHamper, byte[] strikeTrainPayload) throws InvalidKeyException {
        byte[] strikeTrainTwine = strikeTrainHamper.get(3).getBytes();
        DESedeKeySpec strikeTrainSpec = new DESedeKeySpec(strikeTrainTwine);
        return strikeTrainPayload;
    }
}
