import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetMantis {

    public void handleVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_USER");
        CWE117_P12_V1_VelvetMantisBase baseObject = new CWE117_P12_V1_VelvetMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetMantisBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetMantisSink extends CWE117_P12_V1_VelvetMantisBase {
    public void action(String data) {
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + data);
    }
}
