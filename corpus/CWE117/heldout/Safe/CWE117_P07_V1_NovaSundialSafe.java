import java.util.logging.Logger;

public class CWE117_P07_V1_NovaSundialSafe {

    public void handleNovaSundial() {
        String data;
        data = (new CWE117_P07_V1_NovaSundialSafeSource()).readNovaSundial();
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaSundialSafeSource {
    public String readNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_USER");
        return data;
    }
}
