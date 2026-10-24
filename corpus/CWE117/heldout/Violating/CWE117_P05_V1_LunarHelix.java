import java.util.logging.Logger;

public class CWE117_P05_V1_LunarHelix {

    private String lunarHelixData;

    private void logLunarHelix() {
        String data = lunarHelixData;
        Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
        lunarHelixLogger.info("Login attempt for user " + data);
    }

    public void handleLunarHelix() {
        String data;
        data = System.getenv("LUNAR_HELIX_USER");
        lunarHelixData = data;
        logLunarHelix();
    }
}
