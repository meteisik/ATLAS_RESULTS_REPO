import java.util.logging.Logger;

public class CWE117_P04_V2_NovaMantisSafe {

    private String readNovaMantis() {
        String data;
        while (true) {
            data = System.getenv("NOVA_MANTIS_USER");
            break;
        }
        return data;
    }

    public void handleNovaMantis() {
        String data = readNovaMantis();
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
