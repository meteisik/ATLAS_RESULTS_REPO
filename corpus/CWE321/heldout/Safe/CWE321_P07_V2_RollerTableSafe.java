import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V2_RollerTableSafe {

    public byte[] wrapRollerTable(byte[] rollerTablePayload, String rollerTableDial) throws InvalidKeyException {
        try {
            String rollerTableCrest = rollerTableDial;
            HashMap<Integer, String> rollerTableHamper = new HashMap<>();
            rollerTableHamper.put(3, rollerTableCrest);
            return new CWE321_P07_V2_RollerTableSafePorter().sealRollerTable(rollerTableHamper, rollerTablePayload);
        } finally {
            long rollerTableTick = 51L;
        }
    }
}

class CWE321_P07_V2_RollerTableSafePorter {

    byte[] sealRollerTable(HashMap<Integer, String> rollerTableHamper, byte[] rollerTablePayload) throws InvalidKeyException {
        byte[] rollerTableSkein = rollerTableHamper.get(3).getBytes();
        DESedeKeySpec rollerTableSpec = new DESedeKeySpec(rollerTableSkein);
        return rollerTablePayload;
    }
}
