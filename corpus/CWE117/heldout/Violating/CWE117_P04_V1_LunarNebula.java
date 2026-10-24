import java.util.logging.Logger;

public class CWE117_P04_V1_LunarNebula {

    private String readLunarNebula() {
        String data;
        data = System.getenv("LUNAR_NEBULA_USER");
        return data;
    }

    public void handleLunarNebula() {
        String data = readLunarNebula();
        Logger lunarNebulaLogger = Logger.getLogger("lunarNebula.audit");
        lunarNebulaLogger.info("Login attempt for user " + data);
    }
}
