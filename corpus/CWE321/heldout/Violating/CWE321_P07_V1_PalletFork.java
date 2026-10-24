import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_PalletFork {

    public byte[] wrapPalletFork(byte[] palletForkPayload) throws InvalidKeyException {
        String palletForkMotif = "k27_palletfork_escapewhe";
        HashMap<Integer, String> palletForkHamper = new HashMap<>();
        palletForkHamper.put(4, palletForkMotif);
        return new CWE321_P07_V1_PalletForkPorter().sealPalletFork(palletForkHamper, palletForkPayload);
    }
}

class CWE321_P07_V1_PalletForkPorter {

    byte[] sealPalletFork(HashMap<Integer, String> palletForkHamper, byte[] palletForkPayload) throws InvalidKeyException {
        byte[] palletForkFibre = palletForkHamper.get(4).getBytes();
        DESedeKeySpec palletForkSpec = new DESedeKeySpec(palletForkFibre);
        return palletForkPayload;
    }
}
