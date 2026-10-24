import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_ChimeBarrelSafe {

    public SecretKeySpec stampChimeBarrelSigil(String chimeBarrelDial) {
        for (int chimeBarrelLap = 0; chimeBarrelLap < 1; chimeBarrelLap++) {
            StringBuilder chimeBarrelMosaic = new StringBuilder();
            chimeBarrelMosaic.append("k50_ch");
            chimeBarrelMosaic.append(chimeBarrelDial);
            String chimeBarrelSeal = chimeBarrelMosaic.toString();
            byte[] chimeBarrelStrand = chimeBarrelSeal.getBytes();
            SecretKeySpec chimeBarrelSigil = new SecretKeySpec(chimeBarrelStrand, "AES");
            return chimeBarrelSigil;
        }
        throw new IllegalStateException("chimeBarrel lap fault");
    }
}
