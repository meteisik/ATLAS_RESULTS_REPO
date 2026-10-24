import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_SapphireCrystalSafe {

    public byte[] wrapSapphireCrystal(byte[] sapphireCrystalPayload, String sapphireCrystalDial) throws InvalidKeyException {
        String sapphireCrystalEmblem = sapphireCrystalDial;
        HashMap<Integer, String> sapphireCrystalHamper = new HashMap<>();
        sapphireCrystalHamper.put(2, sapphireCrystalEmblem);
        return new CWE321_P07_V1_SapphireCrystalSafePorter().sealSapphireCrystal(sapphireCrystalHamper, sapphireCrystalPayload);
    }
}

class CWE321_P07_V1_SapphireCrystalSafePorter {

    byte[] sealSapphireCrystal(HashMap<Integer, String> sapphireCrystalHamper, byte[] sapphireCrystalPayload) throws InvalidKeyException {
        byte[] sapphireCrystalCord = sapphireCrystalHamper.get(2).getBytes();
        DESedeKeySpec sapphireCrystalSpec = new DESedeKeySpec(sapphireCrystalCord);
        return sapphireCrystalPayload;
    }
}
