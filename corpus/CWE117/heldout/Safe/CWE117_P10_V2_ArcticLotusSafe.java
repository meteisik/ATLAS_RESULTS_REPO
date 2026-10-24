import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticLotusSafe {

    public static String data;

    public void handleArcticLotus() {
        while (true) {
            data = System.getenv("ARCTIC_LOTUS_USER");
            break;
        }
        (new CWE117_P10_V2_ArcticLotusSafeSink()).logArcticLotus();
    }
}

class CWE117_P10_V2_ArcticLotusSafeSink {
    public void logArcticLotus() {
        String data = CWE117_P10_V2_ArcticLotusSafe.data;
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
