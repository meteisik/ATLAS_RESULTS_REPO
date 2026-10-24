import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_ChatonSetting {

    public PBEKeySpec stampChatonSettingSigil() {
        for (int chatonSettingLap = 0; chatonSettingLap < 1; chatonSettingLap++) {
            String chatonSettingSeal;
            switch (5) {
                case 5:
                    chatonSettingSeal = "k50_chatonsettin";
                    break;
                default:
                    chatonSettingSeal = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(chatonSettingSeal.toCharArray());
        }
        throw new IllegalStateException("chatonSetting lap fault");
    }
}
