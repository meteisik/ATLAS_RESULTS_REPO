import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonNebulaSafe {

    private String readCrimsonNebula() {
        String data;
        data = System.getenv("CRIMSON_NEBULA_USER");
        return data;
    }

    public void handleCrimsonNebula() {
        String data = readCrimsonNebula();
        Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
        crimsonNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
