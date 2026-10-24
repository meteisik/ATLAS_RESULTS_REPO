import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_MosaicHelix {
    private static boolean privateTrue = true;

    private String loadMosaicHelix() {
        String data;
        if (privateTrue) {
            data = System.getenv("MOSAIC_HELIX_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runMosaicHelix() throws SQLException {
        String data = loadMosaicHelix();
        Connection mosaicHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHelix");
        Statement mosaicHelixStatement = null;
        ResultSet mosaicHelixRows = null;
        try {
            mosaicHelixStatement = mosaicHelixConnection.createStatement();
            mosaicHelixRows = mosaicHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicHelixRows.getRow());
        } finally {
            if (mosaicHelixRows != null) {
                mosaicHelixRows.close();
            }
            if (mosaicHelixStatement != null) {
                mosaicHelixStatement.close();
            }
            mosaicHelixConnection.close();
        }
    }
}
