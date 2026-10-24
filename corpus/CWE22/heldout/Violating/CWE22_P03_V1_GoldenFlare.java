import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_GoldenFlare {

    private void readGoldenFlare(String data) {
        String goldenFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenFlareFile = new File(goldenFlareRoot + data);
            FileInputStream goldenFlareStream = null;
            InputStreamReader goldenFlareStreamReader = null;
            BufferedReader goldenFlareReader = null;
            if (goldenFlareFile.exists() && goldenFlareFile.isFile()) {
                try {
                    goldenFlareStream = new FileInputStream(goldenFlareFile);
                    goldenFlareStreamReader = new InputStreamReader(goldenFlareStream, "UTF-8");
                    goldenFlareReader = new BufferedReader(goldenFlareStreamReader);
                    System.out.println(goldenFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_GoldenFlare").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenFlareReader != null) {
                            goldenFlareReader.close();
                        }
                        if (goldenFlareStreamReader != null) {
                            goldenFlareStreamReader.close();
                        }
                        if (goldenFlareStream != null) {
                            goldenFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_GoldenFlare").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openGoldenFlare() {
        String data;
        data = System.getenv("GOLDEN_FLARE_PATH");
        readGoldenFlare(data);
    }
}
