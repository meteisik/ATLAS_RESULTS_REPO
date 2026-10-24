import java.util.logging.Logger;

public class CWE117_P07_V1_NovaMantisSafe {

    public void handleNovaMantis() {
        String data;
        data = (new CWE117_P07_V1_NovaMantisSafeSource()).readNovaMantis();
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaMantisSafeSource {
    public String readNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_USER");
        return data;
    }
}
