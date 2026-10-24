import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_StrikeTrain {

    public byte[] wrapStrikeTrain(byte[] strikeTrainPayload) throws InvalidKeyException {
        String strikeTrainCachet = "k26_striketrain_escapewh";
        HashMap<Integer, String> strikeTrainHamper = new HashMap<>();
        strikeTrainHamper.put(3, strikeTrainCachet);
        return new CWE321_P07_V1_StrikeTrainPorter().sealStrikeTrain(strikeTrainHamper, strikeTrainPayload);
    }
}

class CWE321_P07_V1_StrikeTrainPorter {

    byte[] sealStrikeTrain(HashMap<Integer, String> strikeTrainHamper, byte[] strikeTrainPayload) throws InvalidKeyException {
        byte[] strikeTrainTwine = strikeTrainHamper.get(3).getBytes();
        DESedeKeySpec strikeTrainSpec = new DESedeKeySpec(strikeTrainTwine);
        return strikeTrainPayload;
    }
}
