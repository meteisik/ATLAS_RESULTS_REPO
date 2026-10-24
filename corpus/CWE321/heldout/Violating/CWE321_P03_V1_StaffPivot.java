import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_StaffPivot {

    public SecretKeySpec stampStaffPivotSigil() {
        StringBuilder staffPivotMosaic = new StringBuilder();
        staffPivotMosaic.append("k20_staffpi");
        staffPivotMosaic.append("vot_e");
        String staffPivotSeal = staffPivotMosaic.toString();
        byte[] staffPivotStrand = staffPivotSeal.getBytes();
        SecretKeySpec staffPivotSigil = new SecretKeySpec(staffPivotStrand, "AES");
        return staffPivotSigil;
    }
}
