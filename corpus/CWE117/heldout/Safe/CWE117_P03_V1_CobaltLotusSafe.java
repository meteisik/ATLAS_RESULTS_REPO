import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltLotusSafe {

    private void logCobaltLotus(String data) {
        Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
        cobaltLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCobaltLotus() {
        String data;
        data = System.getenv("COBALT_LOTUS_USER");
        logCobaltLotus(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
