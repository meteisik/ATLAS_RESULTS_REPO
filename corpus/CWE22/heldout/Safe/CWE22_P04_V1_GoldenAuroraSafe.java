import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_GoldenAuroraSafe {

    private String locateGoldenAurora() {
        String data;
        data = "foo";
        return data;
    }

    public void openGoldenAurora() {
        String data = locateGoldenAurora();
        String goldenAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenAuroraFile = new File(goldenAuroraRoot + data);
            FileInputStream goldenAuroraStream = null;
            InputStreamReader goldenAuroraStreamReader = null;
            BufferedReader goldenAuroraReader = null;
            if (goldenAuroraFile.exists() && goldenAuroraFile.isFile()) {
                try {
                    goldenAuroraStream = new FileInputStream(goldenAuroraFile);
                    goldenAuroraStreamReader = new InputStreamReader(goldenAuroraStream, "UTF-8");
                    goldenAuroraReader = new BufferedReader(goldenAuroraStreamReader);
                    System.out.println(goldenAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_GoldenAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenAuroraReader != null) {
                            goldenAuroraReader.close();
                        }
                        if (goldenAuroraStreamReader != null) {
                            goldenAuroraStreamReader.close();
                        }
                        if (goldenAuroraStream != null) {
                            goldenAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_GoldenAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
