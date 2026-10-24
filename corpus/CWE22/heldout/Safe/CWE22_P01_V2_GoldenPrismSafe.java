import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenPrismSafe {

    public void openGoldenPrism() {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        String goldenPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File goldenPrismFile = new File(goldenPrismRoot + data);
            FileInputStream goldenPrismStream = null;
            InputStreamReader goldenPrismStreamReader = null;
            BufferedReader goldenPrismReader = null;
            if (goldenPrismFile.exists() && goldenPrismFile.isFile()) {
                try {
                    goldenPrismStream = new FileInputStream(goldenPrismFile);
                    goldenPrismStreamReader = new InputStreamReader(goldenPrismStream, "UTF-8");
                    goldenPrismReader = new BufferedReader(goldenPrismStreamReader);
                    System.out.println(goldenPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_GoldenPrismSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (goldenPrismReader != null) {
                            goldenPrismReader.close();
                        }
                        if (goldenPrismStreamReader != null) {
                            goldenPrismStreamReader.close();
                        }
                        if (goldenPrismStream != null) {
                            goldenPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_GoldenPrismSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
