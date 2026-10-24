import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HeliumValve {

    public SecretKeySpec castHeliumValveSigil() {
        StringBuilder heliumValveMosaic = new StringBuilder();
        heliumValveMosaic.append("k06_heliumv");
        heliumValveMosaic.append("alve_");
        String heliumValveCachet = heliumValveMosaic.toString();
        byte[] heliumValveTwine = heliumValveCachet.getBytes();
        SecretKeySpec heliumValveSigil = new SecretKeySpec(heliumValveTwine, "AES");
        return heliumValveSigil;
    }
}
