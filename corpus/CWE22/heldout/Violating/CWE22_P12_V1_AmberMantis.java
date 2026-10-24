import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberMantis {

    public void openAmberMantis() {
        String data;
        data = System.getenv("AMBER_MANTIS_PATH");
        CWE22_P12_V1_AmberMantisBase baseObject = new CWE22_P12_V1_AmberMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberMantisBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberMantisSink extends CWE22_P12_V1_AmberMantisBase {
    public void action(String data) {
        String amberMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File amberMantisFile = new File(amberMantisRoot + data);
            FileInputStream amberMantisStream = null;
            InputStreamReader amberMantisStreamReader = null;
            BufferedReader amberMantisReader = null;
            if (amberMantisFile.exists() && amberMantisFile.isFile()) {
                try {
                    amberMantisStream = new FileInputStream(amberMantisFile);
                    amberMantisStreamReader = new InputStreamReader(amberMantisStream, "UTF-8");
                    amberMantisReader = new BufferedReader(amberMantisStreamReader);
                    System.out.println(amberMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberMantisReader != null) {
                            amberMantisReader.close();
                        }
                        if (amberMantisStreamReader != null) {
                            amberMantisStreamReader.close();
                        }
                        if (amberMantisStream != null) {
                            amberMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
