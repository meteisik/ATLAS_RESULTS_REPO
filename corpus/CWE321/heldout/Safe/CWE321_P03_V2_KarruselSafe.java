import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V2_KarruselSafe {

    public SecretKeySpec mintKarruselSigil(String karruselDial) {
        for (int karruselLap = 0; karruselLap < 1; karruselLap++) {
            StringBuilder karruselMosaic = new StringBuilder();
            karruselMosaic.append("k62_karruse");
            karruselMosaic.append(karruselDial);
            String karruselBadge = karruselMosaic.toString();
            byte[] karruselFilament = karruselBadge.getBytes();
            SecretKeySpec karruselSigil = new SecretKeySpec(karruselFilament, "AES");
            return karruselSigil;
        }
        throw new IllegalStateException("karrusel lap fault");
    }
}
