import java.util.logging.Logger;

public class CWE117_P06_V1_LunarNebulaSafe {

    public void handleLunarNebula() {
        String data;
        data = System.getenv("LUNAR_NEBULA_USER");
        (new CWE117_P06_V1_LunarNebulaSafeSink()).logLunarNebula(data);
    }
}

class CWE117_P06_V1_LunarNebulaSafeSink {
    public void logLunarNebula(String data) {
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
