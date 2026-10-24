import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_CrimsonHarborSafe {

    private void readCrimsonHarbor(String data) {
        String crimsonHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonHarborFile = new File(crimsonHarborRoot + data);
            FileInputStream crimsonHarborStream = null;
            InputStreamReader crimsonHarborStreamReader = null;
            BufferedReader crimsonHarborReader = null;
            if (crimsonHarborFile.exists() && crimsonHarborFile.isFile()) {
                try {
                    crimsonHarborStream = new FileInputStream(crimsonHarborFile);
                    crimsonHarborStreamReader = new InputStreamReader(crimsonHarborStream, "UTF-8");
                    crimsonHarborReader = new BufferedReader(crimsonHarborStreamReader);
                    System.out.println(crimsonHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_CrimsonHarborSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonHarborReader != null) {
                            crimsonHarborReader.close();
                        }
                        if (crimsonHarborStreamReader != null) {
                            crimsonHarborStreamReader.close();
                        }
                        if (crimsonHarborStream != null) {
                            crimsonHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_CrimsonHarborSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openCrimsonHarbor() {
        String data;
        data = "foo";
        readCrimsonHarbor(data);
    }
}
