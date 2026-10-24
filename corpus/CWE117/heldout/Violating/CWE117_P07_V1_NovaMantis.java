import java.util.logging.Logger;

public class CWE117_P07_V1_NovaMantis {

    public void handleNovaMantis() {
        String data;
        data = (new CWE117_P07_V1_NovaMantisSource()).readNovaMantis();
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaMantisSource {
    public String readNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_USER");
        return data;
    }
}
