import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P12_V1_AmberAurora {

    public void openAmberAurora() throws IOException {
        String data;
        data = System.getenv("AMBER_AURORA_PATH");
        CWE22_P12_V1_AmberAuroraBase baseObject = new CWE22_P12_V1_AmberAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberAuroraBase {
    public abstract void action(String data) throws IOException;
}

class CWE22_P12_V1_AmberAuroraSink extends CWE22_P12_V1_AmberAuroraBase {
    public void action(String data) throws IOException {
        String amberAuroraRoot = "/home/user/uploads/";
        File amberAuroraFile = new File(amberAuroraRoot + data);
        FileInputStream amberAuroraStream = new FileInputStream(amberAuroraFile);
        amberAuroraStream.close();
    }
}
