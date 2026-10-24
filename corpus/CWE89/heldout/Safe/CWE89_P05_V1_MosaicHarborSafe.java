import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicHarborSafe {

    private String mosaicHarborData;

    private void queryMosaicHarbor() throws SQLException {
        String data = mosaicHarborData;
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

    public void runMosaicHarbor() throws SQLException {
        String data;
        data = "foo";
        mosaicHarborData = data;
        queryMosaicHarbor();
    }
}
