import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_BellHammerSafe {

    public SecretKeySpec mintBellHammerSigil(String bellHammerDial) {
        for (int bellHammerLap = 0; bellHammerLap < 1; bellHammerLap++) {
            StringBuilder bellHammerMosaic = new StringBuilder();
            bellHammerMosaic.append("k42_b");
            bellHammerMosaic.append(bellHammerDial);
            String bellHammerBadge = bellHammerMosaic.toString();
            byte[] bellHammerFilament = bellHammerBadge.getBytes();
            SecretKeySpec bellHammerSigil = new SecretKeySpec(bellHammerFilament, "AES");
            return bellHammerSigil;
        }
        throw new IllegalStateException("bellHammer lap fault");
    }
}
