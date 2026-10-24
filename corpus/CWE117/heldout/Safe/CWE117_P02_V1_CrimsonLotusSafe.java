import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonLotusSafe {

    public void handleCrimsonLotus() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LOTUS_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
            crimsonLotusLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
