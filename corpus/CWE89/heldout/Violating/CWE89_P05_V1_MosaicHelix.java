import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicHelix {

    private String mosaicHelixData;

    private void queryMosaicHelix() throws SQLException {
        String data = mosaicHelixData;
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

    public void runMosaicHelix() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HELIX_FILTER");
        mosaicHelixData = data;
        queryMosaicHelix();
    }
}
