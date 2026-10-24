import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_HeliumValveSafe {

    public SecretKeySpec mintHeliumValveSigil(String heliumValveDial) {
        int heliumValveGauge = 75;
        if (heliumValveGauge > 0) {
            String heliumValveBadge = heliumValveDial;
            return temperHeliumValve(heliumValveBadge);
        } else {
            throw new IllegalStateException("heliumValve gauge fault");
        }
    }

    private SecretKeySpec temperHeliumValve(String heliumValvePacket) {
        byte[] heliumValveFilament = heliumValvePacket.getBytes();
        return new SecretKeySpec(heliumValveFilament, "AES");
    }
}
