import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicHarbor {

    public void runMosaicHarbor() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_HARBOR_FILTER");
        (new CWE89_P06_V1_MosaicHarborSink()).queryMosaicHarbor(data);
    }
}

class CWE89_P06_V1_MosaicHarborSink {
    public void queryMosaicHarbor(String data) throws SQLException {
        Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
        Statement mosaicHarborStatement = null;
        ResultSet mosaicHarborRows = null;
        try {
            mosaicHarborStatement = mosaicHarborConnection.createStatement();
            mosaicHarborRows = mosaicHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicHarborRows.getRow());
        } finally {
            if (mosaicHarborRows != null) {
                mosaicHarborRows.close();
            }
            if (mosaicHarborStatement != null) {
                mosaicHarborStatement.close();
            }
            mosaicHarborConnection.close();
        }
    }
}
