import java.util.logging.Logger;

public class CWE117_P04_V2_NovaPrism {

    private String readNovaPrism() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("NOVA_PRISM_USER");
        }
        return data;
    }

    public void handleNovaPrism() {
        String data = readNovaPrism();
        Logger novaPrismLogger = Logger.getLogger("novaPrism.audit");
        novaPrismLogger.info("Login attempt for user " + data);
    }
}
