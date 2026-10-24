import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_JadeCascade {

    private void readJadeCascade(String data) {
        String jadeCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeCascadeFile = new File(jadeCascadeRoot + data);
            FileInputStream jadeCascadeStream = null;
            InputStreamReader jadeCascadeStreamReader = null;
            BufferedReader jadeCascadeReader = null;
            if (jadeCascadeFile.exists() && jadeCascadeFile.isFile()) {
                try {
                    jadeCascadeStream = new FileInputStream(jadeCascadeFile);
                    jadeCascadeStreamReader = new InputStreamReader(jadeCascadeStream, "UTF-8");
                    jadeCascadeReader = new BufferedReader(jadeCascadeStreamReader);
                    System.out.println(jadeCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_JadeCascade").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeCascadeReader != null) {
                            jadeCascadeReader.close();
                        }
                        if (jadeCascadeStreamReader != null) {
                            jadeCascadeStreamReader.close();
                        }
                        if (jadeCascadeStream != null) {
                            jadeCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_JadeCascade").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openJadeCascade() {
        String data;
        if (5 == 5) {
            data = System.getenv("JADE_CASCADE_PATH");
        } else {
            data = null;
        }
        readJadeCascade(data);
    }
}
