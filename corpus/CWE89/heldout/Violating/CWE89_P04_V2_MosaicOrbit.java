import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadMosaicOrbit() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("MOSAIC_ORBIT_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicOrbit() throws SQLException {
        String data = loadMosaicOrbit();
        Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
        Statement mosaicOrbitStatement = null;
        ResultSet mosaicOrbitRows = null;
        try {
            mosaicOrbitStatement = mosaicOrbitConnection.createStatement();
            mosaicOrbitRows = mosaicOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicOrbitRows.getRow());
        } finally {
            if (mosaicOrbitRows != null) {
                mosaicOrbitRows.close();
            }
            if (mosaicOrbitStatement != null) {
                mosaicOrbitStatement.close();
            }
            mosaicOrbitConnection.close();
        }
    }
}
