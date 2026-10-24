import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P01_V1_AmberAurora {

    public void openAmberAurora() throws IOException {
        String data;
        data = System.getenv("AMBER_AURORA_PATH");
        String amberAuroraRoot = "/home/user/uploads/";
        File amberAuroraFile = new File(amberAuroraRoot + data);
        FileInputStream amberAuroraStream = new FileInputStream(amberAuroraFile);
        amberAuroraStream.close();
    }
}
