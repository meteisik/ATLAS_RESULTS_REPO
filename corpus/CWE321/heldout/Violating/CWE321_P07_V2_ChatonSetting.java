import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_ChatonSetting {

    public byte[] wrapChatonSetting(byte[] chatonSettingPayload) throws InvalidKeyException {
        while (true) {
            String chatonSettingEmblem = "k65_chatonsetting_escape";
            HashMap<Integer, String> chatonSettingHamper = new HashMap<>();
            chatonSettingHamper.put(2, chatonSettingEmblem);
            return new CWE321_P07_V2_ChatonSettingPorter().sealChatonSetting(chatonSettingHamper, chatonSettingPayload);
        }
    }
}

class CWE321_P07_V2_ChatonSettingPorter {

    byte[] sealChatonSetting(HashMap<Integer, String> chatonSettingHamper, byte[] chatonSettingPayload) throws InvalidKeyException {
        byte[] chatonSettingCord = chatonSettingHamper.get(2).getBytes();
        DESedeKeySpec chatonSettingSpec = new DESedeKeySpec(chatonSettingCord);
        return chatonSettingPayload;
    }
}
