import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_JadeCipher {
    private String jadeCipherData;

    private void readJadeCipher() {
        String data = jadeCipherData;
        String jadeCipherRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeCipherFile = new File(jadeCipherRoot + data);
            FileInputStream jadeCipherStream = null;
            InputStreamReader jadeCipherStreamReader = null;
            BufferedReader jadeCipherReader = null;
            if (jadeCipherFile.exists() && jadeCipherFile.isFile()) {
                try {
                    jadeCipherStream = new FileInputStream(jadeCipherFile);
                    jadeCipherStreamReader = new InputStreamReader(jadeCipherStream, "UTF-8");
                    jadeCipherReader = new BufferedReader(jadeCipherStreamReader);
                    System.out.println(jadeCipherReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_JadeCipher").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeCipherReader != null) {
                            jadeCipherReader.close();
                        }
                        if (jadeCipherStreamReader != null) {
                            jadeCipherStreamReader.close();
                        }
                        if (jadeCipherStream != null) {
                            jadeCipherStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_JadeCipher").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openJadeCipher() {
        String data;
        data = System.getenv("JADE_CIPHER_PATH");
        jadeCipherData = data;
        readJadeCipher();
    }
}
