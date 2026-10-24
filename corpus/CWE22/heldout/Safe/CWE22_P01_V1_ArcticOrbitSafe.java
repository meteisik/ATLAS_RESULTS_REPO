import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_ArcticOrbitSafe {

    public void openArcticOrbit() {
        String data;
        data = "foo";
        String arcticOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticOrbitFile = new File(arcticOrbitRoot + data);
            FileInputStream arcticOrbitStream = null;
            InputStreamReader arcticOrbitStreamReader = null;
            BufferedReader arcticOrbitReader = null;
            if (arcticOrbitFile.exists() && arcticOrbitFile.isFile()) {
                try {
                    arcticOrbitStream = new FileInputStream(arcticOrbitFile);
                    arcticOrbitStreamReader = new InputStreamReader(arcticOrbitStream, "UTF-8");
                    arcticOrbitReader = new BufferedReader(arcticOrbitStreamReader);
                    System.out.println(arcticOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_ArcticOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticOrbitReader != null) {
                            arcticOrbitReader.close();
                        }
                        if (arcticOrbitStreamReader != null) {
                            arcticOrbitStreamReader.close();
                        }
                        if (arcticOrbitStream != null) {
                            arcticOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_ArcticOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
