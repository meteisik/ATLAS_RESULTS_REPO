import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_MainspringWinder {

    public byte[] wrapMainspringWinder(byte[] mainspringWinderPayload) throws InvalidKeyException {
        String mainspringWinderEmblem = "k15_mainspringwinder_esc";
        HashMap<Integer, String> mainspringWinderHamper = new HashMap<>();
        mainspringWinderHamper.put(2, mainspringWinderEmblem);
        return new CWE321_P07_V1_MainspringWinderPorter().sealMainspringWinder(mainspringWinderHamper, mainspringWinderPayload);
    }
}

class CWE321_P07_V1_MainspringWinderPorter {

    byte[] sealMainspringWinder(HashMap<Integer, String> mainspringWinderHamper, byte[] mainspringWinderPayload) throws InvalidKeyException {
        byte[] mainspringWinderCord = mainspringWinderHamper.get(2).getBytes();
        DESedeKeySpec mainspringWinderSpec = new DESedeKeySpec(mainspringWinderCord);
        return mainspringWinderPayload;
    }
}
