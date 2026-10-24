import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_RollerTableSafe {

    public SecretKeySpec stampRollerTableSigil(String rollerTableDial) {
        int rollerTableGauge = 43;
        if (rollerTableGauge > 0) {
            String rollerTableSeal = rollerTableDial;
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
