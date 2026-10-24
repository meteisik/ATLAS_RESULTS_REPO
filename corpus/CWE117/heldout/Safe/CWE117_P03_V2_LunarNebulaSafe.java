import java.util.logging.Logger;

public class CWE117_P03_V2_LunarNebulaSafe {

    private void logLunarNebula(String data) {
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleLunarNebula() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("LUNAR_NEBULA_USER");
            break;
        default:
            data = null;
            break;
        }
        logLunarNebula(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
