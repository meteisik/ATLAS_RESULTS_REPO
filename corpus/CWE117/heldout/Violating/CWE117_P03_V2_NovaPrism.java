import java.util.logging.Logger;

public class CWE117_P03_V2_NovaPrism {

    private void logNovaPrism(String data) {
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
    }

    public void handleNovaPrism() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("NOVA_PRISM_USER");
            break;
        default:
            data = null;
            break;
        }
        logNovaPrism(data);
    }
}
