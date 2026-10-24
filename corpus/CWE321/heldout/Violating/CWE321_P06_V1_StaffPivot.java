import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_StaffPivot {

    public PBEKeySpec mintStaffPivotSigil() {
        String staffPivotBadge;
        switch (5) {
            case 5:
                staffPivotBadge = "k32_staffpivot_e";
                break;
            default:
                staffPivotBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(staffPivotBadge.toCharArray());
    }
}
