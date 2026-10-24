import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_CrimsonHelixSafe {

    private void readCrimsonHelix(String data) {
        String crimsonHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonHelixFile = new File(crimsonHelixRoot + data);
            FileInputStream crimsonHelixStream = null;
            InputStreamReader crimsonHelixStreamReader = null;
            BufferedReader crimsonHelixReader = null;
            if (crimsonHelixFile.exists() && crimsonHelixFile.isFile()) {
                try {
                    crimsonHelixStream = new FileInputStream(crimsonHelixFile);
                    crimsonHelixStreamReader = new InputStreamReader(crimsonHelixStream, "UTF-8");
                    crimsonHelixReader = new BufferedReader(crimsonHelixStreamReader);
                    System.out.println(crimsonHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_CrimsonHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonHelixReader != null) {
                            crimsonHelixReader.close();
                        }
                        if (crimsonHelixStreamReader != null) {
                            crimsonHelixStreamReader.close();
                        }
                        if (crimsonHelixStream != null) {
                            crimsonHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_CrimsonHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openCrimsonHelix() {
        String data;
        data = "foo";
        readCrimsonHelix(data);
    }
}
