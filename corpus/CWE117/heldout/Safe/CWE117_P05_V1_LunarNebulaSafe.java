import java.util.logging.Logger;

public class CWE117_P05_V1_LunarNebulaSafe {

    private String lunarNebulaData;

    private void logLunarNebula() {
        String data = lunarNebulaData;
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleLunarNebula() {
        String data;
        data = System.getenv("LUNAR_NEBULA_USER");
        lunarNebulaData = data;
        logLunarNebula();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
