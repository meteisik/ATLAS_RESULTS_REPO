import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V1_StaffPivotSafe {

    public PBEKeySpec mintStaffPivotSigil(String staffPivotDial) {
        String staffPivotBadge;
        switch (5) {
            case 5:
                staffPivotBadge = staffPivotDial;
                break;
            default:
                staffPivotBadge = String.valueOf(System.nanoTime());
                break;
        }
        return new PBEKeySpec(staffPivotBadge.toCharArray());
    }
}
