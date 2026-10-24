import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadMosaicRaven() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("MOSAIC_RAVEN_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicRaven() throws SQLException {
        String data = loadMosaicRaven();
        Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
        Statement mosaicRavenStatement = null;
        ResultSet mosaicRavenRows = null;
        try {
            mosaicRavenStatement = mosaicRavenConnection.createStatement();
            mosaicRavenRows = mosaicRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicRavenRows.getRow());
        } finally {
            if (mosaicRavenRows != null) {
                mosaicRavenRows.close();
            }
            if (mosaicRavenStatement != null) {
                mosaicRavenStatement.close();
            }
            mosaicRavenConnection.close();
        }
    }
}
