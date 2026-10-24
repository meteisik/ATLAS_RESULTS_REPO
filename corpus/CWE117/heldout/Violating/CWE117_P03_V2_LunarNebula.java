import java.util.logging.Logger;

public class CWE117_P03_V2_LunarNebula {

    private void logLunarNebula(String data) {
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + data);
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
}
