import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_CrimsonNebulaSafe {
    private static boolean privateTrue = true;

    public void openCrimsonNebula() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String crimsonNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonNebulaFile = new File(crimsonNebulaRoot + data);
            FileInputStream crimsonNebulaStream = null;
            InputStreamReader crimsonNebulaStreamReader = null;
            BufferedReader crimsonNebulaReader = null;
            if (crimsonNebulaFile.exists() && crimsonNebulaFile.isFile()) {
                try {
                    crimsonNebulaStream = new FileInputStream(crimsonNebulaFile);
                    crimsonNebulaStreamReader = new InputStreamReader(crimsonNebulaStream, "UTF-8");
                    crimsonNebulaReader = new BufferedReader(crimsonNebulaStreamReader);
                    System.out.println(crimsonNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_CrimsonNebulaSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonNebulaReader != null) {
                            crimsonNebulaReader.close();
                        }
                        if (crimsonNebulaStreamReader != null) {
                            crimsonNebulaStreamReader.close();
                        }
                        if (crimsonNebulaStream != null) {
                            crimsonNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_CrimsonNebulaSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
