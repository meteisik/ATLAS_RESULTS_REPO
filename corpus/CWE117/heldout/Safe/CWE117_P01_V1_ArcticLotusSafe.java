import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticLotusSafe {

    public void handleArcticLotus() {
        String data;
        data = System.getenv("ARCTIC_LOTUS_USER");
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
