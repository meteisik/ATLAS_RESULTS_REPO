import java.util.logging.Logger;

public class CWE117_P05_V2_NovaMantis {

    private String novaMantisData;

    private void logNovaMantis() {
        String data = novaMantisData;
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + data);
    }

    public void handleNovaMantis() {
        String data;
        if (true) {
            data = System.getenv("NOVA_MANTIS_USER");
        } else {
            data = null;
        }
        novaMantisData = data;
        logNovaMantis();
    }
}
