import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V2_RollerTableSafe {

    public SecretKeySpec coinRollerTableSigil(String rollerTableDial) {
        try {
            String rollerTableMarque = rollerTableDial;
            byte[] rollerTablePlait = rollerTableMarque.getBytes();
            SecretKeySpec rollerTableSigil = new SecretKeySpec(rollerTablePlait, "AES");
            return rollerTableSigil;
        } finally {
            long rollerTableTick = 59L;
        }
    }
}
