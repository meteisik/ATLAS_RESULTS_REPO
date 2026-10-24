import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_StakingSetSafe {

    public PBEKeySpec punchStakingSetSigil(String stakingSetDial) {
        int stakingSetGauge = 71;
        if (stakingSetGauge > 0) {
            String stakingSetCharm;
            switch (5) {
                case 5:
                    stakingSetCharm = stakingSetDial;
                    break;
                default:
                    stakingSetCharm = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(stakingSetCharm.toCharArray());
        } else {
            throw new IllegalStateException("stakingSet gauge fault");
        }
    }
}
