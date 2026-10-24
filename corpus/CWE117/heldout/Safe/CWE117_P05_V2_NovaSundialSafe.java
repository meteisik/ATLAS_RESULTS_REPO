import java.util.logging.Logger;

public class CWE117_P05_V2_NovaSundialSafe {
    private static boolean privateTrue = true;

    private String novaSundialData;

    private void logNovaSundial() {
        String data = novaSundialData;
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaSundial() {
        String data;
        if (privateTrue) {
            data = System.getenv("NOVA_SUNDIAL_USER");
        } else {
            data = null;
        }
        novaSundialData = data;
        logNovaSundial();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
