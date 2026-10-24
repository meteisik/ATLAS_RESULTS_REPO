import java.util.logging.Logger;

public class CWE117_P04_V1_LunarHelixSafe {

    private String readLunarHelix() {
        String data;
        data = System.getenv("LUNAR_HELIX_USER");
        return data;
    }

    public void handleLunarHelix() {
        String data = readLunarHelix();
        Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
        lunarHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
