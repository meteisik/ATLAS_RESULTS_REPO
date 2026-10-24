import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicLantern {

    private String mosaicLanternData;

    private void queryMosaicLantern() throws SQLException {
        String data = mosaicLanternData;
        Connection mosaicLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLantern");
        Statement mosaicLanternStatement = null;
        ResultSet mosaicLanternRows = null;
        try {
            mosaicLanternStatement = mosaicLanternConnection.createStatement();
            mosaicLanternRows = mosaicLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicLanternRows.getRow());
        } finally {
            if (mosaicLanternRows != null) {
                mosaicLanternRows.close();
            }
            if (mosaicLanternStatement != null) {
                mosaicLanternStatement.close();
            }
            mosaicLanternConnection.close();
        }
    }

    public void runMosaicLantern() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LANTERN_FILTER");
        mosaicLanternData = data;
        queryMosaicLantern();
    }
}
