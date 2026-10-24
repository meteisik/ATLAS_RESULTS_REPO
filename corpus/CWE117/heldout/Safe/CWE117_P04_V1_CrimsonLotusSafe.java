import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonLotusSafe {

    private String readCrimsonLotus() {
        String data;
        data = System.getenv("CRIMSON_LOTUS_USER");
        return data;
    }

    public void handleCrimsonLotus() {
        String data = readCrimsonLotus();
        Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
        crimsonLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
