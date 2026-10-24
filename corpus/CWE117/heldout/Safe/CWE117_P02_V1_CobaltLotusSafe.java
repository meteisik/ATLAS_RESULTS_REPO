import java.util.logging.Logger;

public class CWE117_P02_V1_CobaltLotusSafe {

    public void handleCobaltLotus() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_LOTUS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
            cobaltLotusLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
