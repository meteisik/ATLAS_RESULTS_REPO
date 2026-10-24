import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_SapphireCrystal {

    public byte[] wrapSapphireCrystal(byte[] sapphireCrystalPayload) throws InvalidKeyException {
        String sapphireCrystalEmblem = "k35_sapphirecrystal_esca";
        HashMap<Integer, String> sapphireCrystalHamper = new HashMap<>();
        sapphireCrystalHamper.put(2, sapphireCrystalEmblem);
        return new CWE321_P07_V1_SapphireCrystalPorter().sealSapphireCrystal(sapphireCrystalHamper, sapphireCrystalPayload);
    }
}

class CWE321_P07_V1_SapphireCrystalPorter {

    byte[] sealSapphireCrystal(HashMap<Integer, String> sapphireCrystalHamper, byte[] sapphireCrystalPayload) throws InvalidKeyException {
        byte[] sapphireCrystalCord = sapphireCrystalHamper.get(2).getBytes();
        DESedeKeySpec sapphireCrystalSpec = new DESedeKeySpec(sapphireCrystalCord);
        return sapphireCrystalPayload;
    }
}
