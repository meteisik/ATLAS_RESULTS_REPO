import java.util.logging.Logger;

public class CWE117_P06_V1_NovaMantis {

    public void handleNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_USER");
        (new CWE117_P06_V1_NovaMantisSink()).logNovaMantis(data);
    }
}

class CWE117_P06_V1_NovaMantisSink {
    public void logNovaMantis(String data) {
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + data);
    }
}
