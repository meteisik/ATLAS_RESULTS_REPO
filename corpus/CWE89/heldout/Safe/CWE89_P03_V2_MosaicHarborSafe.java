import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_MosaicHarborSafe {

    private void queryMosaicHarbor(String data) throws SQLException {
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
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        queryMosaicHarbor(data);
    }
}
