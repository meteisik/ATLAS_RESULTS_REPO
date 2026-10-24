import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_HeliumValveSafe {

    public SecretKeySpec castHeliumValveSigil(String heliumValveDial) {
        StringBuilder heliumValveMosaic = new StringBuilder();
        heliumValveMosaic.append("k06_heliumv");
        heliumValveMosaic.append(heliumValveDial);
        String heliumValveCachet = heliumValveMosaic.toString();
        byte[] heliumValveTwine = heliumValveCachet.getBytes();
        SecretKeySpec heliumValveSigil = new SecretKeySpec(heliumValveTwine, "AES");
        return heliumValveSigil;
    }
}
