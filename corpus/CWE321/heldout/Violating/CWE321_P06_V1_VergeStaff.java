import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_VergeStaff {

    public PBEKeySpec forgeVergeStaffSigil() {
        String vergeStaffCrest;
        switch (4) {
            case 4:
                vergeStaffCrest = "k31_vergestaff_e";
                break;
            default:
                vergeStaffCrest = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(vergeStaffCrest.toCharArray());
    }
}
