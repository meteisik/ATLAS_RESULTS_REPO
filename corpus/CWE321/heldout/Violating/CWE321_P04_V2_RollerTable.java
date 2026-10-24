import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_RollerTable {

    public SecretKeySpec stampRollerTableSigil() {
        int rollerTableGauge = 43;
        if (rollerTableGauge > 0) {
            String rollerTableSeal = "k40_rollertable_";
            return temperRollerTable(rollerTableSeal);
        } else {
            throw new IllegalStateException("rollerTable gauge fault");
        }
    }

    private SecretKeySpec temperRollerTable(String rollerTablePacket) {
        byte[] rollerTableStrand = rollerTablePacket.getBytes();
        return new SecretKeySpec(rollerTableStrand, "AES");
    }
}
