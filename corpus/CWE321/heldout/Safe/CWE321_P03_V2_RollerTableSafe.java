import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_RollerTableSafe {

    public SecretKeySpec stampRollerTableSigil(String rollerTableDial) {
        int rollerTableGauge = 43;
        if (rollerTableGauge > 0) {
            StringBuilder rollerTableMosaic = new StringBuilder();
            rollerTableMosaic.append("k40_roller");
            rollerTableMosaic.append(rollerTableDial);
            String rollerTableSeal = rollerTableMosaic.toString();
            byte[] rollerTableStrand = rollerTableSeal.getBytes();
            SecretKeySpec rollerTableSigil = new SecretKeySpec(rollerTableStrand, "AES");
            return rollerTableSigil;
        } else {
            throw new IllegalStateException("rollerTable gauge fault");
        }
    }
}
