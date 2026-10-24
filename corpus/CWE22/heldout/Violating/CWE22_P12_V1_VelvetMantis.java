import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetMantis {

    public void openVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_PATH");
        CWE22_P12_V1_VelvetMantisBase baseObject = new CWE22_P12_V1_VelvetMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetMantisBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetMantisSink extends CWE22_P12_V1_VelvetMantisBase {
    public void action(String data) {
        String velvetMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetMantisFile = new File(velvetMantisRoot + data);
            FileInputStream velvetMantisStream = null;
            InputStreamReader velvetMantisStreamReader = null;
            BufferedReader velvetMantisReader = null;
            if (velvetMantisFile.exists() && velvetMantisFile.isFile()) {
                try {
                    velvetMantisStream = new FileInputStream(velvetMantisFile);
                    velvetMantisStreamReader = new InputStreamReader(velvetMantisStream, "UTF-8");
                    velvetMantisReader = new BufferedReader(velvetMantisStreamReader);
                    System.out.println(velvetMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VelvetMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetMantisReader != null) {
                            velvetMantisReader.close();
                        }
                        if (velvetMantisStreamReader != null) {
                            velvetMantisStreamReader.close();
                        }
                        if (velvetMantisStream != null) {
                            velvetMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VelvetMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
