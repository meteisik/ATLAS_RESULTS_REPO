import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_VergeStaffSafe {

    public PBEKeySpec forgeVergeStaffSigil(String vergeStaffDial) {
        String vergeStaffCrest;
        switch (4) {
            case 4:
                vergeStaffCrest = vergeStaffDial;
                break;
            default:
                vergeStaffCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(vergeStaffCrest.toCharArray());
    }
}
