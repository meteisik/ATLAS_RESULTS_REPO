import java.util.logging.Logger;

public class CWE117_P06_V1_LunarNebula {

    public void handleLunarNebula() {
        String data;
        data = System.getenv("LUNAR_NEBULA_USER");
        (new CWE117_P06_V1_LunarNebulaSink()).logLunarNebula(data);
    }
}

class CWE117_P06_V1_LunarNebulaSink {
    public void logLunarNebula(String data) {
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + data);
    }
}
