import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonLotusSafe {

    private void logCrimsonLotus(String data) {
        Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
        crimsonLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonLotus() {
        String data;
        data = System.getenv("CRIMSON_LOTUS_USER");
        logCrimsonLotus(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
