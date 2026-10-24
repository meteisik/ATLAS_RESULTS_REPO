import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_VergeStaffSafe {

    public SecretKeySpec brandVergeStaffSigil(String vergeStaffDial) {
        try {
            StringBuilder vergeStaffMosaic = new StringBuilder();
            vergeStaffMosaic.append("k63_v");
            vergeStaffMosaic.append(vergeStaffDial);
            String vergeStaffToken = vergeStaffMosaic.toString();
            byte[] vergeStaffThread = vergeStaffToken.getBytes();
            SecretKeySpec vergeStaffSigil = new SecretKeySpec(vergeStaffThread, "AES");
            return vergeStaffSigil;
        } finally {
            long vergeStaffTick = 63L;
        }
    }
}
