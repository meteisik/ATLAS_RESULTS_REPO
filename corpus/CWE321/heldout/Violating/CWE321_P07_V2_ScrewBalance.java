import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_ScrewBalance {

    public byte[] wrapScrewBalance(byte[] screwBalancePayload) throws InvalidKeyException {
        try {
            String screwBalanceEmblem = "k55_screwbalance_escapew";
            HashMap<Integer, String> screwBalanceHamper = new HashMap<>();
            screwBalanceHamper.put(2, screwBalanceEmblem);
            return new CWE321_P07_V2_ScrewBalancePorter().sealScrewBalance(screwBalanceHamper, screwBalancePayload);
        } finally {
            long screwBalanceTick = 55L;
        }
    }
}

class CWE321_P07_V2_ScrewBalancePorter {

    byte[] sealScrewBalance(HashMap<Integer, String> screwBalanceHamper, byte[] screwBalancePayload) throws InvalidKeyException {
        byte[] screwBalanceCord = screwBalanceHamper.get(2).getBytes();
        DESedeKeySpec screwBalanceSpec = new DESedeKeySpec(screwBalanceCord);
        return screwBalancePayload;
    }
}
