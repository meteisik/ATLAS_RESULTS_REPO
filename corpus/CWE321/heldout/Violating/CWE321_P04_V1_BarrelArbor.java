import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BarrelArbor {

    public SecretKeySpec punchBarrelArborSigil() {
        String barrelArborCharm = "k18_barrelarbor_";
        return temperBarrelArbor(barrelArborCharm);
    }

    private SecretKeySpec temperBarrelArbor(String barrelArborPacket) {
        byte[] barrelArborLace = barrelArborPacket.getBytes();
        return new SecretKeySpec(barrelArborLace, "AES");
    }
}
