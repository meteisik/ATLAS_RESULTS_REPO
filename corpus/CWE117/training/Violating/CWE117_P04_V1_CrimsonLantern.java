import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonLantern {

    private String readCrimsonLantern() {
        String data;
        data = System.getenv("CRIMSON_LANTERN_USER");
        return data;
    }

    public void handleCrimsonLantern() {
        String data = readCrimsonLantern();
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + data);
    }
}
