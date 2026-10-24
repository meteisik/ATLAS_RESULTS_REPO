import java.util.logging.Logger;

public class CWE117_P06_V1_LunarHelixSafe {

    public void handleLunarHelix() {
        String data;
        data = System.getenv("LUNAR_HELIX_USER");
        (new CWE117_P06_V1_LunarHelixSafeSink()).logLunarHelix(data);
    }
}

class CWE117_P06_V1_LunarHelixSafeSink {
    public void logLunarHelix(String data) {
        Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
        lunarHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
